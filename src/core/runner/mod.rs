//! Process-wide shared state.
//!
//! Nginx modules keep configuration in cycle/shm pools reachable from the request
//! context. Rust needs an explicit owner instead: the HTTP core creates a
//! [`ControlPlane`] once at startup and modules look their state up by type. This keeps
//! per-request code free of `unsafe` statics and makes every shared dependency explicit.

pub mod control;
