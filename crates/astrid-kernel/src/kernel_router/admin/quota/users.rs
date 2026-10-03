//! Operator-only discovery for ambiguous legacy resource attribution.

use super::super::handlers::{err_bad_input, err_internal, success_json};
use crate::kernel_router::{AuthorizedRequest, authorize_request};
use astrid_core::PrincipalId;
use astrid_events::kernel_api::AdminResponseBody;
use std::sync::Arc;

pub(crate) async fn list(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    authorization: Option<&AuthorizedRequest>,
    device_key_id: Option<&str>,
) -> AdminResponseBody {
    // The recovery roster is global. A self-scoped device must not borrow
    // its principal's broader capabilities, even through internal dispatch.
    let resolved;
    let authority = if let Some(authority) = authorization {
        authority
    } else {
        resolved = match authorize_request(kernel, caller, device_key_id, "quota:set") {
            Ok(authority) => authority,
            Err(error) => return err_bad_input(error.to_string()),
        };
        &resolved
    };
    if let Err(error) = authority.capability_check().require("quota:set") {
        return err_bad_input(error.to_string());
    }
    match kernel.ownership_store.load().await {
        Ok(graph) => success_json(serde_json::json!(graph.users().collect::<Vec<_>>())),
        Err(error) => err_internal(error.to_string()),
    }
}
