//! Host-owned request context exposed as opaque comparison handles.

use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::net::host::{ErrorCode, TcpStream};
use crate::engine::wasm::bindings::astrid::request_context::host as request_context;
use crate::engine::wasm::host_state::{HostState, NetStream};

impl request_context::Host for HostState {
    fn connection_owner(
        &mut self,
        connection: Resource<TcpStream>,
    ) -> Result<Option<String>, ErrorCode> {
        self.resource_table
            .get::<NetStream>(&Resource::new_borrow(connection.rep()))
            .map_err(|_| ErrorCode::InvalidHandle)?;

        Ok(self
            .connection_principals
            .get(&connection.rep())
            .map(|identity| identity.request_owner.to_string()))
    }

    fn connection_principal(
        &mut self,
        connection: Resource<TcpStream>,
    ) -> Result<Option<String>, ErrorCode> {
        self.resource_table
            .get::<NetStream>(&Resource::new_borrow(connection.rep()))
            .map_err(|_| ErrorCode::InvalidHandle)?;

        Ok(self
            .connection_principals
            .get(&connection.rep())
            .map(|identity| identity.principal.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::engine::wasm::host_state::TcpStreamSlot;
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    #[tokio::test(flavor = "current_thread")]
    async fn request_context_exposes_only_the_host_bound_identity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listener address");
        let connect = tokio::spawn(async move {
            tokio::net::TcpStream::connect(address)
                .await
                .expect("connect loopback")
        });
        let (accepted, _) = listener.accept().await.expect("accept loopback");
        let _peer = connect.await.expect("join connector");

        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        let rep = state
            .resource_table
            .push(NetStream::Tcp(TcpStreamSlot {
                stream: Arc::new(tokio::sync::Mutex::new(accepted)),
                read_timeout: None,
                write_timeout: None,
            }))
            .expect("push stream")
            .rep();

        assert_eq!(
            request_context::Host::connection_principal(&mut state, Resource::new_borrow(rep))
                .expect("unbound stream lookup"),
            None
        );

        let principal = astrid_core::PrincipalId::new("alice").expect("valid principal");
        state.bind_connection_principal(rep, principal, Some("device-alice".to_owned()));

        assert_eq!(
            request_context::Host::connection_principal(&mut state, Resource::new_borrow(rep))
                .expect("bound stream lookup")
                .as_deref(),
            Some("alice")
        );
        assert!(
            request_context::Host::connection_principal(
                &mut state,
                Resource::new_borrow(rep.wrapping_add(1))
            )
            .is_err(),
            "an unknown resource handle must fail closed"
        );
    }
}
