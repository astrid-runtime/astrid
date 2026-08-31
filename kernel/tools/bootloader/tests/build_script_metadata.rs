// Exercise the build-script parser through Cargo's test harness. The parser
// remains in build.rs because it is only needed while selecting the nested
// target for the build-script cargo invocation.
#[path = "../build.rs"]
#[allow(dead_code, unused_imports)]
mod build_script;
