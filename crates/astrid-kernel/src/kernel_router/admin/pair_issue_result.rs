//! Translate the durable insertion and terminal policy result into pairing outcomes.

use vstd::prelude::*;

verus! {

pub(super) enum PairIssueError {
    BadInput(String),
    Unauthorized(String),
    Internal(String),
}

pub(super) enum Inserted<T> {
    Issued(T),
    Collision,
    Unavailable,
}

pub(super) fn finish<T, E>(stored: &Result<bool, E>, token: T) -> (result: Inserted<T>)
    ensures match stored {
        Ok(true) => result == Inserted::Issued(token),
        Ok(false) => result is Collision,
        Err(_) => result is Unavailable,
    },
{
    match stored {
        Ok(true) => Inserted::Issued(token),
        Ok(false) => Inserted::Collision,
        Err(_) => Inserted::Unavailable,
    }
}

pub(super) enum Audit<'a> {
    Success,
    Denied(&'a String),
    Failure(&'a String),
}

pub(super) fn audit<T>(result: &Result<T, PairIssueError>) -> (row: Audit<'_>)
    ensures match result {
        Ok(_) => row is Success,
        Err(PairIssueError::Unauthorized(error)) => row == Audit::Denied(error),
        Err(PairIssueError::Internal(error)) => row == Audit::Failure(error),
        Err(PairIssueError::BadInput(error)) => row == Audit::Failure(error),
    },
{
    match result {
        Ok(_) => Audit::Success,
        Err(PairIssueError::Unauthorized(error)) => Audit::Denied(error),
        Err(PairIssueError::BadInput(error) | PairIssueError::Internal(error)) => Audit::Failure(error),
    }
}

}
