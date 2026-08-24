use super::{
    AdminKernelRequest, AdminKernelResponse, AdminRequestKind, AdminResponseBody, CommandKind,
};

impl CommandKind {
    /// Returns `true` for the default kind so serializers can omit it
    /// (matches the rest of the manifest fields' conventions).
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Slash)
    }
}

impl AdminKernelRequest {
    /// Build a request with no correlation ID.
    #[must_use]
    pub const fn new(kind: AdminRequestKind) -> Self {
        Self {
            request_id: None,
            kind,
        }
    }

    /// Build a request with a correlation ID.
    #[must_use]
    pub fn with_request_id(request_id: impl Into<String>, kind: AdminRequestKind) -> Self {
        Self {
            request_id: Some(request_id.into()),
            kind,
        }
    }
}

impl From<AdminRequestKind> for AdminKernelRequest {
    fn from(kind: AdminRequestKind) -> Self {
        Self::new(kind)
    }
}

impl AdminKernelResponse {
    /// Build a response with the given body and no correlation ID.
    #[must_use]
    pub const fn new(body: AdminResponseBody) -> Self {
        Self {
            request_id: None,
            body,
        }
    }

    /// Build a response that echoes a request's correlation ID.
    #[must_use]
    pub fn for_request(request_id: Option<String>, body: AdminResponseBody) -> Self {
        Self { request_id, body }
    }
}

impl AdminRequestKind {
    /// Host-internal fact: this request must bind alias+`PrincipalUid` at
    /// admin ingress before profile or capability lookup.
    ///
    /// Not a wire field. Connection identity remains `PrincipalId`.
    #[must_use]
    pub const fn requires_principal_identity(&self) -> bool {
        matches!(
            self,
            Self::StorageMountIssue { .. }
                | Self::StorageMountStatus { .. }
                | Self::StorageMountSync { .. }
                | Self::StorageMountRevoke { .. }
        )
    }
}
