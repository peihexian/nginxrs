//! Module state that a rebuilt request state needs, published after compilation.
//!
//! The phase engine builds `RequestState` from a snapshot when it continues a request after a
//! phase handler (a `return`, a proxy response, a redirect). Module variables such as the
//! `geoip_*` family read their configuration from the state, exactly like nginx reads `gcf`
//! from the module's main configuration, so the published configuration is copied back in.

use crate::core::http::RequestState;

impl RequestState {
    /// Copy the published module configuration into this state.
    pub fn apply_published_modules(&mut self) {
        if self.get::<crate::modules::geoip::conf::Conf>().is_none()
            && let Some(conf) = crate::modules::geoip::published()
        {
            self.insert(conf);
        }
    }
}
