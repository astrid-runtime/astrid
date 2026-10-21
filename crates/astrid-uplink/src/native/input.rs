//! Bounded connection input admission and independently scheduled control.

use super::{
    AuthenticatedIdentity, EventBus, IpcMessage, IpcPayload, LocalWriteHalf, Topic, egress,
    private_elicit, process_inbound, routing, validate_ingress, write_ingress_refusal,
    write_message,
};

type InputSlots<'a, 'b> = (
    &'b mut Option<PendingInput<'a>>,
    &'b mut Option<PendingInput<'a>>,
    &'b mut Option<PendingInput<'a>>,
);

pub(super) struct PendingInput<'a> {
    pub(super) chat_session: Option<String>,
    pub(super) starts_turn: bool,
    pub(super) future:
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), &'static str>> + Send + 'a>>,
}

impl<'a> PendingInput<'a> {
    pub(super) fn new(
        bus: &'a EventBus,
        identity: &'a AuthenticatedIdentity,
        receiver: &'a egress::Subscription,
        message: IpcMessage,
    ) -> Self {
        let chat_session = input_chat_session(&message);
        let starts_turn = chat_session.is_some() && !routing::is_cancel_turn(&message.payload);
        Self {
            chat_session,
            starts_turn,
            future: Box::pin(process_inbound(
                bus,
                identity,
                identity.principal.as_str(),
                receiver,
                message,
            )),
        }
    }
}

pub(super) fn input_chat_session(message: &IpcMessage) -> Option<String> {
    (message.topic.as_str() == routing::CHAT_REQUEST_TOPIC).then(|| {
        routing::payload_session_id(&message.payload)
            .unwrap_or("default")
            .to_owned()
    })
}

pub(super) async fn wait_pending(input: &mut Option<PendingInput<'_>>) -> Result<(), &'static str> {
    match input.as_mut() {
        Some(input) => input.future.as_mut().await,
        None => std::future::pending().await,
    }
}

pub(super) async fn complete_pending(
    writer: &mut LocalWriteHalf,
    identity: &AuthenticatedIdentity,
    input: &mut Option<PendingInput<'_>>,
    result: Result<(), &'static str>,
) -> std::io::Result<()> {
    let session = input.take().and_then(|input| input.chat_session);
    if let Err(reason) = result {
        write_ingress_refusal(writer, identity, session, reason).await
    } else {
        Ok(())
    }
}

pub(super) async fn handle_connection_input<'a>(
    writer: &mut LocalWriteHalf,
    bus: &'a EventBus,
    identity: &'a AuthenticatedIdentity,
    receiver: &'a egress::Subscription,
    private_elicits: Option<&dyn private_elicit::PrivateElicitResponder>,
    message: IpcMessage,
    inputs: InputSlots<'a, '_>,
) -> std::io::Result<()> {
    let (pending, control, cancellation) = inputs;
    // A buffered next frame may win select! before the newly created future
    // has ever been polled. Settle ready admission before calling it blocked.
    let turn_waits_for_cancel = cancellation.is_some();
    for slot in [&mut *pending, &mut *control, &mut *cancellation] {
        if turn_waits_for_cancel && slot.as_ref().is_some_and(|input| input.starts_turn) {
            continue;
        }
        settle_ready_input(writer, identity, slot).await?;
    }
    // Cancellation may have completed in the loop after the prompt was
    // skipped. Give that prompt its admission opportunity before deciding
    // whether the incoming management frame would exceed the bounded slot.
    if turn_waits_for_cancel && cancellation.is_none() {
        settle_ready_input(writer, identity, pending).await?;
    }
    if message.topic.as_str() == private_elicit::REPLY_TOPIC {
        let response = private_elicit::respond(identity, private_elicits, message);
        write_message(writer, &response).await
    } else if message.topic.as_str() == routing::CHAT_REQUEST_TOPIC
        && routing::is_cancel_turn(&message.payload)
    {
        if pending.as_ref().is_some_and(|input| input.starts_turn) {
            return cancel_pending_input(
                writer,
                identity,
                receiver,
                &message,
                pending,
                cancellation.is_some(),
            )
            .await;
        }
        if cancellation.is_none() {
            *cancellation = Some(PendingInput::new(bus, identity, receiver, message));
            return Ok(());
        }
        write_ingress_refusal(
            writer,
            identity,
            input_chat_session(&message),
            "previous cancellation is awaiting runtime delivery",
        )
        .await
    } else if pending.is_some() {
        if receiver
            .human_reply_owner(&message)
            .is_ok_and(|owner| owner.is_some())
        {
            if control.is_none() {
                *control = Some(PendingInput::new(bus, identity, receiver, message));
                return Ok(());
            }
            return write_ingress_refusal(
                writer,
                identity,
                None,
                "previous human reply is awaiting runtime delivery",
            )
            .await;
        }
        // Bound admission to one input, but keep reading so EOF remains
        // observable. Additional requests receive an explicit private refusal.
        write_ingress_refusal(
            writer,
            identity,
            input_chat_session(&message),
            "previous input is awaiting runtime delivery",
        )
        .await
    } else {
        *pending = Some(PendingInput::new(bus, identity, receiver, message));
        Ok(())
    }
}

async fn settle_ready_input(
    writer: &mut LocalWriteHalf,
    identity: &AuthenticatedIdentity,
    input: &mut Option<PendingInput<'_>>,
) -> std::io::Result<()> {
    let ready = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(input.as_mut().and_then(
            |input| match input.future.as_mut().poll(cx) {
                std::task::Poll::Ready(result) => Some(result),
                std::task::Poll::Pending => None,
            },
        ))
    })
    .await;
    if let Some(result) = ready {
        complete_pending(writer, identity, input, result).await?;
    }
    Ok(())
}

async fn cancel_pending_input(
    writer: &mut LocalWriteHalf,
    identity: &AuthenticatedIdentity,
    receiver: &egress::Subscription,
    message: &IpcMessage,
    pending: &mut Option<PendingInput<'_>>,
    retirement_pending: bool,
) -> std::io::Result<()> {
    let session = input_chat_session(message);
    if let Err(reason) = validate_ingress(message) {
        return write_ingress_refusal(writer, identity, session, reason).await;
    }
    let Some(session_id) = session.filter(|session| {
        pending
            .as_ref()
            .filter(|input| input.starts_turn)
            .and_then(|input| input.chat_session.as_ref())
            == Some(session)
    }) else {
        return write_ingress_refusal(
            writer,
            identity,
            input_chat_session(message),
            "cancellation does not match this connection's pending session",
        )
        .await;
    };
    let owner = receiver.turn_owner().unwrap_or(identity.request_owner);
    // No publication has committed while the admission future is pending.
    // Dropping it rolls back the captured turn and releases all reservations.
    drop(pending.take());
    // The queued successor was never admitted while the original cancellation
    // waited. Discard it, but let that original cancellation acknowledge its
    // own retirement once; an early second terminal would carry the old owner.
    if retirement_pending {
        return Ok(());
    }
    let terminal = IpcMessage::new(
        Topic::from_raw("agent.v1.response"),
        IpcPayload::AgentResponse {
            text: "Request cancelled.".into(),
            is_final: true,
            session_id,
        },
        uuid::Uuid::nil(),
    )
    .with_principal(identity.principal.as_str())
    .with_request_owner(owner);
    write_message(writer, &terminal).await
}
