#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::de::DeserializeOwned;

fuzz_target!(|data: &[u8]| {
    try_parse::<astrid_gateway::routes::agent::ApprovalResponseRequest>(data);
    try_parse::<astrid_gateway::routes::agent::ElicitResponseRequest>(data);
    try_parse::<astrid_gateway::routes::agent::PromptRequest>(data);
    try_parse::<astrid_gateway::routes::auth::PairDeviceIssueRequest>(data);
    try_parse::<astrid_gateway::routes::auth::PairDeviceRedeemRequest>(data);
    try_parse::<astrid_gateway::routes::auth::RedeemRequest>(data);
    try_parse::<astrid_gateway::routes::caps::GrantRequest>(data);
    try_parse::<astrid_gateway::routes::caps::RevokeRequest>(data);
    try_parse::<astrid_gateway::routes::capsules::InstallRequest>(data);
    try_parse::<astrid_gateway::routes::env::EnvWriteRequest>(data);
    try_parse::<astrid_gateway::routes::groups::CreateGroupRequest>(data);
    try_parse::<astrid_gateway::routes::groups::ModifyGroupRequest>(data);
    try_parse::<astrid_gateway::routes::invites::IssueRequest>(data);
    try_parse::<astrid_gateway::routes::models::SetActiveModelRequest>(data);
    try_parse::<astrid_gateway::routes::principals::CreatePrincipalRequest>(data);
    try_parse::<astrid_gateway::routes::principals::ModifyPrincipalRequest>(data);
    try_parse::<astrid_gateway::routes::quotas::QuotaRequest>(data);
    try_parse::<astrid_gateway::routes::sessions::SessionUpdateRequest>(data);
});

fn try_parse<T>(data: &[u8])
where
    T: DeserializeOwned,
{
    let _ = serde_json::from_slice::<T>(data);
}
