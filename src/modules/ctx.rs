//! Context passed to request-phase handlers.
//!
//! This is the boundary between the HTTP core and modules: a module sees the session it
//! may write to, the per-request state, the selected location, the module-specific
//! configuration attached to that location, and the `http {}`-level MIME configuration.

use crate::core::http::RequestState;
use crate::modules::http_core::MimeConfig;
use crate::modules::location::{Location, LocationConf};
use pingora_proxy::Session;

pub struct ModuleCtx<'a> {
    pub session: &'a mut Session,
    pub state: &'a mut RequestState,
    pub location: &'a Location,
    pub server_name: &'a str,
    /// `types` / `default_type` from the `http {}` block.
    pub mime: MimeConfig,
    /// Pattern of the selected location (`^~ /a/`, `~ \.php$`, …), for `root`/`alias` mapping.
    pub prefix: String,
    pub responded: bool,
}

impl<'a> ModuleCtx<'a> {
    pub fn new(
        session: &'a mut Session,
        state: &'a mut RequestState,
        location: &'a Location,
        server_name: &'a str,
    ) -> Self {
        Self::with_mime(session, state, location, server_name, MimeConfig::default())
    }

    /// Attach the selected location pattern, used by `root`/`alias` mapping.
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_string();
        self
    }

    pub fn with_mime(
        session: &'a mut Session,
        state: &'a mut RequestState,
        location: &'a Location,
        server_name: &'a str,
        mime: MimeConfig,
    ) -> Self {
        Self {
            session,
            state,
            location,
            server_name,
            mime,
            prefix: String::new(),
            responded: false,
        }
    }

    pub fn mark_responded(&mut self) {
        self.responded = true;
    }

    pub fn outcome(&self) -> crate::core::Outcome {
        if self.responded {
            crate::core::Outcome::Stop
        } else {
            crate::core::Outcome::Defer
        }
    }

    /// Module configuration attached to this location.
    pub fn conf<T: LocationConf>(&self) -> Option<&T> {
        self.location.get::<T>()
    }

    pub fn error(&self, message: impl std::fmt::Display) -> pingora_core::BError {
        pingora_core::Error::explain(pingora_core::ErrorType::InternalError, message.to_string())
    }
}
