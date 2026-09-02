use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};

use super::handle_daemon_event;
use super::state::App;

fn app() -> App {
    App::new("workspace".to_owned(), String::new(), "00000000".to_owned())
}

#[test]
fn active_model_changed_updates_empty_host_label() {
    let mut app = app();
    let message = IpcMessage::new(
        Topic::from_raw("registry.v1.active_model_changed"),
        IpcPayload::Custom {
            data: serde_json::json!({"id": "capsule/model"}),
        },
        uuid::Uuid::nil(),
    );

    handle_daemon_event(&mut app, &message);

    assert_eq!(app.model_name, "capsule/model");
}

#[test]
fn set_active_model_response_updates_empty_host_label() {
    let mut app = app();
    let message = IpcMessage::new(
        Topic::from_raw("registry.v1.response.set_active_model"),
        IpcPayload::Custom {
            data: serde_json::json!({"active_model": {"id": "capsule/model"}}),
        },
        uuid::Uuid::nil(),
    );

    handle_daemon_event(&mut app, &message);

    assert_eq!(app.model_name, "capsule/model");
}
