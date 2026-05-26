//! Mock implementations for testing.

use std::sync::{Arc, Mutex};

/// Mock event bus for capturing emitted events.
///
/// Uses `std::sync::Mutex` for simplicity and sync/async compatibility.
#[derive(Debug, Clone, Default)]
pub struct MockEventBus {
    /// Captured events.
    events: Arc<Mutex<Vec<MockEvent>>>,
}

/// A captured event.
#[derive(Debug, Clone)]
pub struct MockEvent {
    /// Event type/name.
    pub event_type: String,
    /// Event payload as JSON.
    pub payload: serde_json::Value,
}

impl MockEventBus {
    /// Create a new mock event bus.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Emit an event.
    pub fn emit(&self, event_type: impl Into<String>, payload: serde_json::Value) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(MockEvent {
                event_type: event_type.into(),
                payload,
            });
        }
    }

    /// Get all captured events.
    #[must_use]
    pub fn get_events(&self) -> Vec<MockEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Get events of a specific type.
    #[must_use]
    pub fn get_events_of_type(&self, event_type: &str) -> Vec<MockEvent> {
        self.events
            .lock()
            .map(|g| {
                g.iter()
                    .filter(|e| e.event_type == event_type)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clear all captured events.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.events.lock() {
            guard.clear();
        }
    }

    /// Check if any event of the given type was emitted.
    #[must_use]
    pub fn has_event(&self, event_type: &str) -> bool {
        self.events
            .lock()
            .is_ok_and(|g| g.iter().any(|e| e.event_type == event_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_event_bus() {
        let bus = MockEventBus::new();

        bus.emit("test_event", serde_json::json!({"key": "value"}));
        bus.emit("other_event", serde_json::json!({}));

        assert!(bus.has_event("test_event"));
        assert!(!bus.has_event("nonexistent"));

        let test_events = bus.get_events_of_type("test_event");
        assert_eq!(test_events.len(), 1);
    }
}
