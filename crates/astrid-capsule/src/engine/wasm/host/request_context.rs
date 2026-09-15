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
}
