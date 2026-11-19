//! Type-erased storage for module configuration state.
//!
//! A module owns its state type (e.g. `MainState`, `AccessLogConfig`, `Upstreams`). The
//! configuration compiler keeps every slot alive and hands directive handlers a typed
//! [`StateAccess`], so the HTTP core never lists concrete module types.

use std::any::Any;

/// One state slot plus the module name it belongs to.
pub type StateSlot = (&'static str, StateInstance);

/// A freshly created module state.
///
/// Lookups always go through [`StateInstance::get_ref`] / [`StateInstance::get_mut`],
/// i.e. through the concrete type. Casting a `&mut dyn ModuleState` to `dyn Any` reports
/// the trait object's own type (`dyn ModuleState`) and can never match `MainState`.
pub struct StateInstance(Box<dyn Any + Send>);

impl StateInstance {
    pub fn new<T: Any + Send>(value: T) -> Self {
        Self(Box::new(value))
    }

    pub fn get_ref<T: 'static>(&self) -> Option<&T> {
        (*self.0).downcast_ref::<T>()
    }

    pub fn get_mut<T: 'static>(&mut self) -> Option<&mut T> {
        (*self.0).downcast_mut::<T>()
    }

    pub fn into_any(self) -> Box<dyn Any + Send> {
        self.0
    }

    pub fn type_name(&self) -> &'static str {
        std::any::type_name_of_val(&*self.0)
    }
}

impl std::fmt::Debug for StateInstance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateInstance")
            .field("type", &self.type_name())
            .finish()
    }
}

/// Mutable view of every state slot, passed to directive handlers so each module can reach
/// its own typed state.
pub struct StateAccess<'a> {
    states: &'a mut [StateSlot],
}

impl<'a> StateAccess<'a> {
    pub fn new(states: &'a mut [StateSlot]) -> Self {
        Self { states }
    }

    /// Borrow the slots immutably (read-back after the compile passes).
    pub fn new_readonly(states: &'a [StateSlot]) -> StateRead<'a> {
        StateRead { states }
    }

    pub fn get<T: 'static>(&self, module: &str) -> Option<&T> {
        self.states
            .iter()
            .find(|(name, _)| *name == module)
            .and_then(|(_, state)| state.get_ref())
    }

    pub fn get_mut<T: 'static>(&mut self, module: &str) -> Option<&mut T> {
        self.states
            .iter_mut()
            .find(|(name, _)| *name == module)
            .and_then(|(_, state)| state.get_mut())
    }
}

/// Read-only view of every state slot.
pub struct StateRead<'a> {
    states: &'a [StateSlot],
}

impl<'a> StateRead<'a> {
    pub fn get<T: 'static>(&self, module: &str) -> Option<&T> {
        self.states
            .iter()
            .find(|(name, _)| *name == module)
            .and_then(|(_, state)| state.get_ref())
    }
}

/// Compiled module states, keyed by module name.
#[derive(Default)]
pub struct States {
    entries: Vec<StateSlot>,
}

impl States {
    pub fn get<T: 'static>(&self, module: &str) -> Option<&T> {
        self.entries
            .iter()
            .find(|(name, _)| *name == module)
            .and_then(|(_, state)| state.get_ref())
    }

    pub fn insert(&mut self, module: &'static str, state: StateInstance) {
        self.entries.push((module, state));
    }

    pub fn into_entries(self) -> Vec<StateSlot> {
        self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct Demo(usize);

    #[test]
    fn typed_access_round_trip() {
        let mut slots: Vec<StateSlot> = vec![("demo", StateInstance::new(Demo(1)))];
        {
            let mut access = StateAccess::new(&mut slots);
            assert_eq!(access.get::<Demo>("demo"), Some(&Demo(1)));
            access.get_mut::<Demo>("demo").unwrap().0 = 7;
        }
        assert_eq!(slots[0].1.get_ref::<Demo>(), Some(&Demo(7)));
    }
}
