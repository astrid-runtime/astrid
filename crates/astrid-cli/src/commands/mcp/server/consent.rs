//! Dual-era consent state machine for `tools/call`.

use super::{
    AstridMcpServer, CallFlow, CallToolRequestParams, CallToolResponse, CallToolResult,
    ConsentProtocol, ConsentResolution, ContentBlock, GrantStep, McpError, RequestContext,
    ResolvedConsent, RoleServer, TOOL_CALL_TOPIC, ToolInvocation, Value,
    call_tool_result_from_reply, consent_denied_result, elicit, grant_denied_result, ingress,
    new_req_id, next_grant_step,
};

impl AstridMcpServer {
    pub(super) async fn resume_mrtr(
        &self,
        invocation: &ToolInvocation,
        request: &CallToolRequestParams,
        protocol: ConsentProtocol,
    ) -> Result<CallFlow<usize>, McpError> {
        let Some(state) = request.request_state.as_deref() else {
            if request.input_responses.is_some() {
                return Err(McpError::invalid_params(
                    "inputResponses requires requestState",
                    None,
                ));
            }
            return Ok(CallFlow::Continue(0));
        };
        if matches!(protocol, ConsentProtocol::Legacy) {
            return Err(McpError::invalid_params(
                "requestState requires MCP 2026-07-28",
                None,
            ));
        }

        let ResolvedConsent {
            decision,
            redemption,
        } = self.mrtr.resolve(
            &self.principal,
            &invocation.name,
            &invocation.arguments,
            state,
            request.input_responses.as_ref(),
        )?;
        match decision {
            ConsentResolution::Ingress(approved) => {
                let granted = !approved || self.record_ingress_accept().await?;
                redemption.commit();
                if approved && granted {
                    Ok(CallFlow::Continue(0))
                } else {
                    Ok(CallFlow::Complete(consent_denied_result()))
                }
            },
            ConsentResolution::Grant {
                request,
                approved,
                grants_resolved,
            } => {
                let granted = self.forward_grant_decision(&request, approved).await?;
                redemption.commit();
                if granted {
                    Ok(CallFlow::Continue(grants_resolved.saturating_add(1)))
                } else {
                    Ok(CallFlow::Complete(grant_denied_result()))
                }
            },
            ConsentResolution::Approval { request, choice } => {
                let reply = self
                    .forward_approval_decision(&request, choice.verb())
                    .await?;
                redemption.commit();
                Ok(CallFlow::Complete(
                    call_tool_result_from_reply(&reply).into(),
                ))
            },
        }
    }

    pub(super) async fn invoke_tool(&self, invocation: &ToolInvocation) -> Result<Value, McpError> {
        let req_id = new_req_id();
        self.round_trip(TOOL_CALL_TOPIC, &req_id, invocation.body(&req_id))
            .await
    }

    pub(super) async fn handle_ingress(
        &self,
        reply: Value,
        invocation: &ToolInvocation,
        context: &RequestContext<RoleServer>,
        protocol: ConsentProtocol,
    ) -> Result<CallFlow<Value>, McpError> {
        let Some(request) = ingress::IngressRequest::from_reply(&reply) else {
            return Ok(CallFlow::Continue(reply));
        };
        match protocol {
            ConsentProtocol::Modern {
                supports_form: true,
            } => Ok(CallFlow::Complete(self.mrtr.ingress_required(
                &self.principal,
                &invocation.name,
                &invocation.arguments,
                request.prompt(),
            )?)),
            ConsentProtocol::Modern {
                supports_form: false,
            } => Ok(CallFlow::Complete(consent_denied_result())),
            ConsentProtocol::Legacy => {
                if self.resolve_ingress(&context.peer, &request).await? {
                    Ok(CallFlow::Continue(self.invoke_tool(invocation).await?))
                } else {
                    Ok(CallFlow::Complete(consent_denied_result()))
                }
            },
        }
    }

    pub(super) async fn handle_grants(
        &self,
        mut reply: Value,
        invocation: &ToolInvocation,
        context: &RequestContext<RoleServer>,
        protocol: ConsentProtocol,
        mut grants_resolved: usize,
    ) -> Result<CallFlow<Value>, McpError> {
        loop {
            let grant = match next_grant_step(&reply, grants_resolved) {
                GrantStep::Terminal => return Ok(CallFlow::Continue(reply)),
                GrantStep::Fail(message) => {
                    return Ok(CallFlow::Complete(
                        CallToolResult::error(vec![ContentBlock::text(message)]).into(),
                    ));
                },
                GrantStep::Resolve(grant) => grant,
            };
            match protocol {
                ConsentProtocol::Modern {
                    supports_form: true,
                } => {
                    let prompt = grant.prompt();
                    return Ok(CallFlow::Complete(self.mrtr.grant_required(
                        &self.principal,
                        &invocation.name,
                        &invocation.arguments,
                        grant,
                        grants_resolved,
                        prompt,
                    )?));
                },
                ConsentProtocol::Modern {
                    supports_form: false,
                } => {
                    let _ = self.forward_grant_decision(&grant, false).await?;
                    return Ok(CallFlow::Complete(grant_denied_result()));
                },
                ConsentProtocol::Legacy => {
                    if !self.resolve_grant(&context.peer, &grant).await? {
                        return Ok(CallFlow::Complete(grant_denied_result()));
                    }
                    grants_resolved = grants_resolved.saturating_add(1);
                    reply = self.invoke_tool(invocation).await?;
                },
            }
        }
    }

    pub(super) async fn finish_approval(
        &self,
        reply: Value,
        invocation: &ToolInvocation,
        context: &RequestContext<RoleServer>,
        protocol: ConsentProtocol,
    ) -> Result<CallToolResponse, McpError> {
        let Some(approval) = elicit::ApprovalRequest::from_reply(&reply) else {
            return Ok(call_tool_result_from_reply(&reply).into());
        };
        match protocol {
            ConsentProtocol::Modern {
                supports_form: true,
            } => {
                let prompt = approval.prompt();
                self.mrtr.approval_required(
                    &self.principal,
                    &invocation.name,
                    &invocation.arguments,
                    approval,
                    prompt,
                )
            },
            ConsentProtocol::Modern {
                supports_form: false,
            } => {
                let reply = self
                    .forward_approval_decision(&approval, elicit::ApprovalChoice::Deny.verb())
                    .await?;
                Ok(call_tool_result_from_reply(&reply).into())
            },
            ConsentProtocol::Legacy => {
                let reply = self.resolve_approval(&context.peer, &approval).await?;
                Ok(call_tool_result_from_reply(&reply).into())
            },
        }
    }
}
