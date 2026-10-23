//! Durable-engine tests split by responsibility for reviewable coverage.
use super::locations::LocationLookup as _;

include!("test_cases/foundation.rs");
include!("test_cases/representations.rs");
include!("test_cases/operations_tests.rs");
