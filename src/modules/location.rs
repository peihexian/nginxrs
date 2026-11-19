//! Per-location (and per-server) storage of module configurations.
//!
//! Nginx keeps one `void *loc_conf` slot per module and merges the parent's value into
//! a child location when the module permits inheritance. `Location` reproduces that
//! with a typed map: each module stores its own configuration type, and the HTTP core
//! never references concrete module types.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

/// A module's configuration for one location/server.
pub trait LocationConf: Clone + Send + Sync + 'static {
    /// Whether a child location inherits this value. Location-only modules (for example
    /// `realip`, whose directives are `NGX_HTTP_LOC_CONF` without a merge) return
    /// `false` so children start from their default instead.
    fn inherit(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct Entry {
    value: Arc<dyn Any + Send + Sync>,
    inherit: bool,
}

/// Typed map of module configurations.
#[derive(Clone, Default)]
pub struct Location {
    entries: HashMap<TypeId, Entry>,
}

impl std::fmt::Debug for Location {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Location")
            .field("modules", &self.entries.len())
            .finish()
    }
}

impl Location {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set<T: LocationConf>(&mut self, value: T) {
        let inherit = value.inherit();
        self.entries.insert(
            TypeId::of::<T>(),
            Entry {
                value: Arc::new(value),
                inherit,
            },
        );
    }

    pub fn get<T: LocationConf>(&self) -> Option<&T> {
        self.entries
            .get(&TypeId::of::<T>())
            .and_then(|entry| entry.value.downcast_ref::<T>())
    }

    pub fn get_mut<T: LocationConf>(&mut self) -> Option<&mut T> {
        let entry = self.entries.get_mut(&TypeId::of::<T>())?;
        // Inherited values are shared with the parent; clone before mutating so the
        // parent keeps its own configuration (Nginx copies `loc_conf` on merge).
        if Arc::get_mut(&mut entry.value).is_none() {
            let cloned: Box<dyn Any + Send + Sync> =
                entry.value.downcast_ref::<T>().map(|value| {
                    let boxed: Box<dyn Any + Send + Sync> = Box::new(value.clone());
                    boxed
                })?;
            entry.value = Arc::from(cloned);
        }
        Arc::get_mut(&mut entry.value)?.downcast_mut::<T>()
    }

    pub fn has<T: LocationConf>(&self) -> bool {
        self.entries.contains_key(&TypeId::of::<T>())
    }

    /// Copy inheritable configuration from `parent` into entries the child did not
    /// define itself (Nginx `ngx_http_merge_locations`).
    pub fn inherit_from(&mut self, parent: &Location) {
        for (id, entry) in &parent.entries {
            if entry.inherit && !self.entries.contains_key(id) {
                self.entries.insert(*id, entry.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct Inheritable(usize);
    impl LocationConf for Inheritable {}

    #[derive(Clone, Debug, PartialEq)]
    struct LocalOnly(usize);
    impl LocationConf for LocalOnly {
        fn inherit(&self) -> bool {
            false
        }
    }

    #[test]
    fn inheritance_respects_flags() {
        let mut parent = Location::new();
        parent.set(Inheritable(1));
        parent.set(LocalOnly(2));
        let mut child = Location::new();
        child.inherit_from(&parent);
        assert_eq!(child.get::<Inheritable>(), Some(&Inheritable(1)));
        assert_eq!(child.get::<LocalOnly>(), None);

        child.set(Inheritable(9));
        let mut grandchild = Location::new();
        grandchild.inherit_from(&child);
        assert_eq!(grandchild.get::<Inheritable>(), Some(&Inheritable(9)));
    }

    #[test]
    fn get_mut_is_copy_on_write() {
        let mut parent = Location::new();
        parent.set(Inheritable(1));
        let mut child = Location::new();
        child.inherit_from(&parent);
        child.get_mut::<Inheritable>().unwrap().0 = 5;
        assert_eq!(parent.get::<Inheritable>(), Some(&Inheritable(1)));
        assert_eq!(child.get::<Inheritable>(), Some(&Inheritable(5)));
    }
}
