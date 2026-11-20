//! Upstream response buffering (`proxy_buffering`, `proxy_buffers`, `proxy_buffer_size`,
//! `proxy_busy_buffers_size`, `proxy_max_temp_file_size`, `proxy_temp_path`,
//! `proxy_limit_rate`).
//!
//! The behaviour mirrors Nginx's event pipe (`ngx_event_pipe_read_upstream` /
//! `ngx_event_pipe_write_to_downstream`): a response is collected into `number` buffers of
//! `size` bytes; when the free buffers run out and the temporary file has room the data is
//! spooled to `proxy_temp_path`, and at most `proxy_busy_buffers_size` bytes are held back
//! from the client at a time. With `proxy_buffering off` Nginx forwards every chunk as it
//! arrives (`ngx_http_upstream_process_non_buffered_upstream`).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Where the response body currently lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Storage {
    /// In memory (`p->free_bufs` still had a spare buffer).
    Memory,
    /// Spooled to the temporary file (`ngx_event_pipe_write_chain_to_temp_file`).
    TempFile,
}

/// Result of one `push`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Push {
    /// The chunk was kept in memory.
    Buffered,
    /// The free buffers were exhausted and the chunk went to the temporary file.
    Spooled,
}

/// One response's buffering state.
///
/// `buffers` is `(number, size)` and `busy` is `proxy_busy_buffers_size`; both follow Nginx's
/// merge rules, where `proxy_busy_buffers_size` defaults to `2 * proxy_buffer_size`.
#[derive(Debug)]
pub struct ResponseBuffer {
    buffers: usize,
    buffer_size: usize,
    busy: usize,
    max_temp_file_size: u64,
    temp_path: Option<PathBuf>,
    used: usize,
    total: usize,
    temp_offset: u64,
    storage: Storage,
    temp_file: Option<PathBuf>,
    rate: Option<usize>,
    rate_started: Instant,
    rate_sent: usize,
}

impl ResponseBuffer {
    pub fn new(
        buffering: bool,
        buffers: (usize, usize),
        busy_buffers_size: Option<usize>,
        max_temp_file_size: usize,
        temp_path: Option<PathBuf>,
        limit_rate: Option<usize>,
    ) -> Self {
        // `proxy_buffering off` keeps `p->bufs` but bypasses the pipe entirely
        // (`ngx_http_upstream_process_non_buffered_upstream`), so `buffers == 0` marks it.
        let (number, size) = if buffering {
            (buffers.0.max(1), buffers.1.max(1))
        } else {
            (0, 0)
        };
        // `ngx_http_upstream_merge_loc_conf`: busy size is `2 * proxy_buffer_size` unless set.
        let busy = busy_buffers_size.unwrap_or(size.saturating_mul(2)).max(1);
        Self {
            buffers: number,
            buffer_size: size,
            busy,
            max_temp_file_size: max_temp_file_size as u64,
            temp_path,
            used: 0,
            total: 0,
            temp_offset: 0,
            storage: Storage::Memory,
            temp_file: None,
            rate: limit_rate.filter(|rate| *rate > 0),
            rate_started: Instant::now(),
            rate_sent: 0,
        }
    }

    /// `proxy_buffering off`: every chunk is forwarded immediately.
    pub fn is_streaming(&self) -> bool {
        self.buffers == 0
    }

    /// Accept one upstream chunk (`ngx_event_pipe_read_upstream`).
    pub fn push(&mut self, length: usize) -> Push {
        self.total += length;
        if self.is_streaming() {
            return Push::Buffered;
        }
        self.used += length;
        // Free buffers are counted in `proxy_buffers` units of `proxy_buffer_size`.
        if self.used <= self.buffers * self.buffer_size {
            self.storage = Storage::Memory;
            return Push::Buffered;
        }
        // `p->cacheable || p->temp_file->offset < p->max_temp_file_size`.
        self.temp_offset += length as u64;
        if self.temp_offset <= self.max_temp_file_size {
            self.storage = Storage::TempFile;
            Push::Spooled
        } else {
            // `proxy_max_temp_file_size 0` (and an exhausted temp file) means "stream it":
            // the data is written through to the client instead.
            self.storage = Storage::Memory;
            self.used = self.buffers * self.buffer_size;
            Push::Buffered
        }
    }

    /// Whether the downstream must pause: more than `proxy_busy_buffers_size` is pending
    /// (`ngx_event_pipe_write_to_downstream` only sends when the busy chain is small enough).
    pub fn downstream_busy(&self) -> bool {
        if self.is_streaming() {
            return false;
        }
        self.used > self.busy
    }

    /// Bytes the client has been sent; resets the in-memory accounting.
    pub fn flush(&mut self, sent: usize) {
        self.used = self.used.saturating_sub(sent);
    }

    pub fn storage(&self) -> Storage {
        self.storage
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// `proxy_temp_path` plus the per-request file name Nginx derives (`ngx_temp_file_name`).
    pub fn temp_file_path(&self) -> Option<PathBuf> {
        let directory = self.temp_path.as_deref()?;
        Some(temp_path_for(directory, self.rate_started.elapsed(), self.total))
    }

    pub fn set_temp_file(&mut self, path: PathBuf) {
        self.temp_file = Some(path);
    }

    pub fn temp_file(&self) -> Option<&Path> {
        self.temp_file.as_deref()
    }

    /// `proxy_limit_rate`: how long the client side must wait before more data may be sent.
    ///
    /// Nginx limits the *downstream* transfer rate with a timer per write; here the same
    /// budget is computed from the bytes already sent.
    pub fn rate_delay(&mut self, queued: usize) -> Option<Duration> {
        let rate = self.rate?;
        self.rate_sent += queued;
        rate_delay_for(self.rate_sent, rate, self.rate_started.elapsed())
    }
}

/// Pure form of the rate budget: how long `sent` bytes at `rate` bytes/second still owe.
fn rate_delay_for(sent: usize, rate: usize, elapsed: Duration) -> Option<Duration> {
    let expected = Duration::from_secs_f64(sent as f64 / rate as f64);
    expected.checked_sub(elapsed).filter(|delay| !delay.is_zero())
}

/// Filename Nginx generates for a spooled response (`ngx_temp_file_name`): the process id,
/// a per-request counter and the current time.
fn temp_path_for(directory: &Path, _elapsed: Duration, total: usize) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|now| now.as_nanos())
        .unwrap_or_default();
    directory.join(format!(
        "{:010}{:010}",
        total,
        stamp % 10_000_000_000
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer(buffering: bool, number: usize, size: usize, max_temp: usize) -> ResponseBuffer {
        ResponseBuffer::new(buffering, (number, size), None, max_temp, None, None)
    }

    #[test]
    fn small_response_stays_in_memory() {
        let mut response = buffer(true, 8, 4096, 1024 * 1024);
        assert_eq!(response.push(100), Push::Buffered);
        assert_eq!(response.storage(), Storage::Memory);
        assert!(!response.downstream_busy());
    }

    #[test]
    fn full_buffers_spool_to_the_temporary_file() {
        let mut response = buffer(true, 2, 16, 1024 * 1024);
        assert_eq!(response.push(16), Push::Buffered);
        assert_eq!(response.push(16), Push::Buffered);
        assert_eq!(response.push(16), Push::Spooled);
        assert_eq!(response.storage(), Storage::TempFile);
    }

    #[test]
    fn zero_max_temp_file_size_streams_instead_of_spooling() {
        let mut response = buffer(true, 1, 8, 0);
        assert_eq!(response.push(8), Push::Buffered);
        assert_eq!(response.push(8), Push::Buffered);
        assert_eq!(response.storage(), Storage::Memory);
    }

    #[test]
    fn buffering_off_streams_every_chunk() {
        let mut response = buffer(false, 8, 4096, 1024);
        assert!(response.is_streaming());
        assert_eq!(response.push(1_000_000), Push::Buffered);
        assert!(!response.downstream_busy());
    }

    #[test]
    fn busy_buffers_size_limits_pending_data() {
        // `proxy_buffer_size 4096` makes the default busy size 8192.
        let mut response = buffer(true, 8, 4096, 1024 * 1024);
        response.push(4096);
        assert!(!response.downstream_busy());
        response.push(4096);
        assert!(!response.downstream_busy());
        response.push(1);
        assert!(response.downstream_busy());
        response.flush(response.used);
        assert!(!response.downstream_busy());
    }

    #[test]
    fn limit_rate_delays_the_client_side() {
        // 1000 bytes at 1000 B/s owes one second, minus whatever has already elapsed.
        assert_eq!(
            rate_delay_for(1000, 1000, Duration::ZERO),
            Some(Duration::from_secs(1))
        );
        assert_eq!(rate_delay_for(1000, 1000, Duration::from_secs(1)), None);
        assert_eq!(
            rate_delay_for(2000, 1000, Duration::from_millis(500)),
            Some(Duration::from_millis(1500))
        );
        // Over-running the budget never yields a negative delay.
        assert_eq!(rate_delay_for(100, 1000, Duration::from_secs(5)), None);
    }

    #[test]
    fn temp_path_is_under_the_configured_directory() {
        let mut response = ResponseBuffer::new(
            true,
            (1, 1),
            None,
            1024,
            Some(PathBuf::from("/tmp/proxy")),
            None,
        );
        response.push(8);
        let path = response.temp_file_path().unwrap();
        assert_eq!(path.parent().unwrap(), Path::new("/tmp/proxy"));
    }
}
