//! Capsule management commands - install, list, and inspect capsules.

pub(crate) mod build;
pub(crate) mod check;
pub(crate) mod config;
pub(crate) mod deps;
pub(crate) mod install;
mod install_batch;
mod install_finish;
mod install_github;
mod install_headless;
pub(crate) mod install_prompts;
pub(crate) mod install_update;
pub(crate) mod list;
pub(crate) mod live_load;
pub(crate) mod local_egress;
pub(crate) mod meta;
pub(crate) mod model_discovery;
pub(crate) mod new;
pub(crate) mod new_templates;
pub(crate) mod remove;
pub(crate) mod show;
