//! The process-wide control plane.
//!
//! Modules publish long-lived state (upstream balancers, log writers, Lua pools) here
//! once during startup. The HTTP core hands each request a reference to the plane, so
//! module handlers never touch global mutable state directly.

use std::any::{Any, TypeId};
use std::collections::HashMap;

/// Marker trait for state a module publishes to the control plane.
pub trait ControlPlane: Any + Send + Sync + 'static {}

#[derive(Default)]
pub struct Control {
    entries: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Control {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) {
        self.entries.insert(TypeId::of::<T>(), Box::new(value));
    }

    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.entries
            .get(&TypeId::of::<T>())
            .and_then(|value| value.downcast_ref::<T>())
    }

    pub fn contains<T: 'static>(&self) -> bool {
        self.entries.contains_key(&TypeId::of::<T>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Marker(&'static str);

    #[test]
    fn typed_lookup() {
        let mut control = Control::new();
        control.insert(Marker("realip"));
        assert_eq!(control.get::<Marker>().map(|m| m.0), Some("realip"));
        assert!(!control.contains::<u32>());
    }
}
