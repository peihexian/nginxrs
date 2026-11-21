//! SSI include resolution against the filesystem.
//!
//! `ngx_http_ssi_include` never reads files itself: `virtual=` issues a subrequest that goes
//! through location matching and the content handlers, while `file=` (and a relative
//! `virtual=`) resolves inside the current location. The static serving path has no request
//! pipeline of its own, so this resolver reads the target from disk the way the static and
//! index modules would: the location's `root`/`alias` mapping, then `index` for directories.

use super::conf::SsiConf;
use super::filter::IncludeResolver;
use crate::core::http::RequestState;
use crate::modules::location::Location;
use crate::modules::static_files::StaticConf;

/// Resolves includes of one SSI page.
pub struct LocationIncludes<'a> {
    pub conf: &'a SsiConf,
    pub location: &'a Location,
    pub state: &'a RequestState,
}

impl IncludeResolver for LocationIncludes<'_> {
    fn resolve(&mut self, uri: &str, _file: bool) -> Result<Vec<u8>, String> {
        let _ = self.conf;
        let Some(static_conf) = self.location.get::<StaticConf>() else {
            return Err("no root or alias configured for the include".to_string());
        };
        let root = static_conf
            .alias
            .clone()
            .or_else(|| static_conf.root.clone())
            .ok_or_else(|| "no root or alias configured for the include".to_string())?;
        let (path, _args) = match uri.split_once('?') {
            Some((path, args)) => (path, Some(args)),
            None => (uri, None),
        };
        let relative = path.trim_start_matches('/');
        let mut target = root.join(relative);
        if relative.is_empty() || target.is_dir() {
            let mut found = None;
            for index in static_conf.index.as_deref().unwrap_or(&[]) {
                if index.contains('/') {
                    continue;
                }
                let candidate = target.join(index);
                if candidate.is_file() {
                    found = Some(candidate);
                    break;
                }
            }
            if let Some(found) = found {
                target = found;
            }
        }
        match std::fs::read(&target) {
            Ok(body) => Ok(body),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(format!("{} not found", target.display()))
            }
            Err(error) => Err(format!("{}: {error}", target.display())),
        }
    }
}
