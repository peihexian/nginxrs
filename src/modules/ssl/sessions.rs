//! `ssl_session_cache`, `ssl_session_tickets` and `ssl_session_ticket_key`.
//!
//! Nginx's session cache keeps `ssl_session_cache` entries per zone and counts `hits`
//! against `size` before looking for the oldest entry (`ngx_http_ssl_module.c`,
//! `ngx_ssl_session_cache`). The shared zone is `size` * 1000 bytes / 128 bytes per entry;
//! `builtin` keeps 2048 entries per worker.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// One cached TLS session (`SSL_SESSION` in Nginx terms).
#[derive(Clone, Debug)]
pub struct CachedSession {
    pub data: Vec<u8>,
    /// Monotonic tick of the last use, used for the oldest-entry eviction.
    pub stamp: u64,
}

/// A bounded cache with Nginx's `hits/size` accounting.
#[derive(Debug, Default)]
pub struct SessionCache {
    entries: HashMap<Vec<u8>, CachedSession>,
    hits: u64,
    capacity: usize,
    stamps: u64,
}

impl SessionCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            ..Self::default()
        }
    }

    /// `ssl_session_cache shared:NAME:SIZE` → `(SIZE * 1000) / 128` entries (Nginx uses
    /// `ngx_pagesize` but reserves 128 bytes of metadata per session).
    pub fn for_zone_size(size: usize) -> Self {
        Self::new(size.saturating_mul(1000) / 128)
    }

    pub fn get(&mut self, key: &[u8]) -> Option<Arc<Vec<u8>>> {
        self.stamps += 1;
        let stamp = self.stamps;
        let entry = self.entries.get_mut(key)?;
        entry.stamp = stamp;
        self.hits += 1;
        Some(Arc::new(entry.data.clone()))
    }

    pub fn put(&mut self, key: Vec<u8>, data: Vec<u8>) {
        self.stamps += 1;
        let stamp = self.stamps;
        if self.entries.len() >= self.capacity {
            // `ngx_ssl_session_cache`: replace the oldest entry once the cache is full.
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, session)| session.stamp)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, CachedSession { data, stamp });
        self.hits = self.hits.saturating_sub(0);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// One process-wide cache, shared by every server that references the same zone name.
#[derive(Debug, Default)]
pub struct SharedCaches {
    zones: Mutex<HashMap<String, Arc<Mutex<SessionCache>>>>,
}

impl SharedCaches {
    pub fn zone(&self, name: &str, size: Option<usize>) -> Arc<Mutex<SessionCache>> {
        let mut zones = self.zones.lock();
        zones
            .entry(name.to_string())
            .or_insert_with(|| {
                let cache = match size {
                    Some(size) => SessionCache::for_zone_size(size),
                    None => SessionCache::new(2048),
                };
                Arc::new(Mutex::new(cache))
            })
            .clone()
    }
}

/// `ssl_session_ticket_key` material: a 48 byte key (16 byte name + 16 byte HMAC key +
/// 16 byte AES key) or a 80 byte key, as Nginx validates in `ngx_ssl_session_ticket_keys`.
pub const TICKET_KEY_BYTES: usize = 48;
pub const TICKET_KEY_BYTES_V2: usize = 80;

/// A loaded ticket key.
#[derive(Clone, Debug)]
pub struct TicketKey {
    pub name: [u8; 16],
    pub hmac: [u8; 16],
    pub aes: [u8; 16],
    /// Second key (`80` byte file) used as the prepended key name in AES-256 tickets.
    pub name_v2: Option<[u8; 16]>,
    pub hmac_v2: Option<[u8; 16]>,
    pub aes_v2: Option<[u8; 32]>,
}

impl TicketKey {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            TICKET_KEY_BYTES => Some(Self {
                name: bytes[0..16].try_into().ok()?,
                hmac: bytes[16..32].try_into().ok()?,
                aes: bytes[32..48].try_into().ok()?,
                name_v2: None,
                hmac_v2: None,
                aes_v2: None,
            }),
            TICKET_KEY_BYTES_V2 => Some(Self {
                name: bytes[0..16].try_into().ok()?,
                hmac: bytes[16..32].try_into().ok()?,
                aes: bytes[32..48].try_into().ok()?,
                name_v2: bytes[48..64].try_into().ok(),
                hmac_v2: bytes[64..80].try_into().ok(),
                aes_v2: bytes[80..112].try_into().ok(),
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_evicts_the_oldest_entry() {
        let mut cache = SessionCache::new(2);
        cache.put(b"a".to_vec(), vec![1]);
        cache.put(b"b".to_vec(), vec![2]);
        assert!(cache.get(b"a").is_some());
        // Inserting a third session evicts "b", the least recently used one.
        cache.put(b"c".to_vec(), vec![3]);
        assert!(cache.get(b"a").is_some());
        assert!(cache.get(b"b").is_none());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn zone_size_follows_nginx_accounting() {
        let cache = SessionCache::for_zone_size(1);
        // 1m → 1_000_000 bytes / 128 bytes per session.
        assert_eq!(cache.capacity(), 7812);
    }

    #[test]
    fn ticket_key_sizes_match_nginx() {
        assert!(TicketKey::from_bytes(&[0u8; 48]).is_some());
        assert!(TicketKey::from_bytes(&[0u8; 80]).is_some());
        assert!(TicketKey::from_bytes(&[0u8; 47]).is_none());
    }
}
