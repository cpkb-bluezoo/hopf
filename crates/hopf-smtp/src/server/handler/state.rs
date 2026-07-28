// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Accept/reject state traits for each SMTP stage.

use super::{
    HelloHandler, MailFromHandler, MessageDataHandler, RecipientHandler,
};

/// Operations right after connect (220 / 554 / 421).
pub trait ConnectedState {
    /// Accept with greeting banner; transition to hello stage.
    fn accept_connection(&mut self, greeting: &str, handler: Box<dyn HelloHandler>);
    /// Reject (554) and close.
    fn reject_connection(&mut self) {
        self.reject_connection_msg("Transaction failed");
    }
    /// Reject with custom text (554) and close.
    fn reject_connection_msg(&mut self, message: &str);
    /// Shutting down (421) and close.
    fn server_shutting_down(&mut self);
}

/// Operations for HELO/EHLO response.
pub trait HelloState {
    /// Accept greeting → mail-from ready (250 / EHLO ads).
    fn accept_hello(&mut self, handler: Box<dyn MailFromHandler>);
    /// Temporary reject (421).
    fn reject_hello_temporary(&mut self, message: &str, handler: Box<dyn HelloHandler>);
    /// Permanent reject (550).
    fn reject_hello(&mut self, message: &str, handler: Box<dyn HelloHandler>);
    /// Reject and close (554).
    fn reject_hello_and_close(&mut self, message: &str);
    /// Generic reject.
    fn reject(&mut self, code: u16, text: &str) {
        let _ = (code, text);
    }
    /// Shutting down.
    fn server_shutting_down(&mut self);
}

/// AUTH PLAIN success policy.
pub trait AuthenticateState {
    /// Accept (235) → mail-from ready.
    fn accept(&mut self, handler: Box<dyn MailFromHandler>);
    /// Reject (535); stay in hello.
    fn reject(&mut self, handler: Box<dyn HelloHandler>);
    /// Reject and close.
    fn reject_and_close(&mut self);
    /// Shutting down.
    fn server_shutting_down(&mut self);
}

/// MAIL FROM accept/reject.
pub trait MailFromState {
    /// Accept sender (250) → recipient stage.
    fn accept_sender(&mut self, handler: Box<dyn RecipientHandler>);
    /// Greylist (450).
    fn reject_sender_greylist(&mut self, handler: Box<dyn MailFromHandler>) {
        self.reject(450, "4.7.1 Greylisted", handler);
    }
    /// Rate limit (450).
    fn reject_sender_rate_limit(&mut self, handler: Box<dyn MailFromHandler>) {
        self.reject(450, "4.7.1 Rate limit exceeded", handler);
    }
    /// Storage full (452).
    fn reject_sender_storage_full(&mut self, handler: Box<dyn MailFromHandler>) {
        self.reject(452, "4.3.1 Insufficient system storage", handler);
    }
    /// Blocked domain (550).
    fn reject_sender_blocked_domain(&mut self, handler: Box<dyn MailFromHandler>) {
        self.reject(550, "5.7.1 Sender domain blocked", handler);
    }
    /// Invalid domain (550).
    fn reject_sender_invalid_domain(&mut self, handler: Box<dyn MailFromHandler>) {
        self.reject(550, "5.1.8 Sender domain invalid", handler);
    }
    /// Policy (553).
    fn reject_sender_policy(&mut self, message: &str, handler: Box<dyn MailFromHandler>) {
        self.reject(553, message, handler);
    }
    /// Spam (554).
    fn reject_sender_spam(&mut self, handler: Box<dyn MailFromHandler>) {
        self.reject(554, "5.7.1 Message rejected as spam", handler);
    }
    /// Syntax (501).
    fn reject_sender_syntax(&mut self, handler: Box<dyn MailFromHandler>) {
        self.reject(501, "5.1.7 Bad sender address syntax", handler);
    }
    /// Generic reject with code/text.
    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn MailFromHandler>);
    /// Shutting down.
    fn server_shutting_down(&mut self);
}

/// RCPT TO accept/reject.
pub trait RecipientState {
    /// Accept (250).
    fn accept_recipient(&mut self, handler: Box<dyn RecipientHandler>);
    /// Forward notice (251).
    fn accept_recipient_forward(&mut self, forward_path: &str, handler: Box<dyn RecipientHandler>) {
        let _ = forward_path;
        self.accept_recipient(handler);
    }
    /// Unavailable (450).
    fn reject_recipient_unavailable(&mut self, handler: Box<dyn RecipientHandler>) {
        self.reject(450, "4.2.1 Mailbox unavailable", handler);
    }
    /// Not found (550).
    fn reject_recipient_not_found(&mut self, handler: Box<dyn RecipientHandler>) {
        self.reject(550, "5.1.1 Mailbox unavailable", handler);
    }
    /// Relay denied (551).
    fn reject_recipient_relay_denied(&mut self, handler: Box<dyn RecipientHandler>) {
        self.reject(551, "5.7.1 Relay denied", handler);
    }
    /// Policy (553).
    fn reject_recipient_policy(&mut self, message: &str, handler: Box<dyn RecipientHandler>) {
        self.reject(553, message, handler);
    }
    /// Generic reject.
    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn RecipientHandler>);
    /// Shutting down.
    fn server_shutting_down(&mut self);
}

/// DATA/BDAT start.
pub trait MessageStartState {
    /// Ready for content (354 for DATA).
    fn accept_message(&mut self, handler: Box<dyn MessageDataHandler>);
    /// Storage full (452).
    fn reject_message_storage_full(&mut self, handler: Box<dyn RecipientHandler>) {
        self.reject(452, "4.3.1 Insufficient system storage", handler);
    }
    /// Permanent reject (550) → back to mail-from.
    fn reject_message(&mut self, message: &str, handler: Box<dyn MailFromHandler>);
    /// Generic reject while staying in recipient stage.
    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn RecipientHandler>);
    /// Shutting down.
    fn server_shutting_down(&mut self);
}

/// After message bytes complete.
pub trait MessageEndState {
    /// Accept delivery (250); `queue_id` optional.
    fn accept_message_delivery(
        &mut self,
        queue_id: Option<&str>,
        handler: Box<dyn MailFromHandler>,
    );
    /// Temporary reject (450).
    fn reject_message_temporary(&mut self, message: &str, handler: Box<dyn MailFromHandler>) {
        self.reject(450, message, handler);
    }
    /// Permanent reject (550).
    fn reject_message_permanent(&mut self, message: &str, handler: Box<dyn MailFromHandler>) {
        self.reject(550, message, handler);
    }
    /// Policy (553).
    fn reject_message_policy(&mut self, message: &str, handler: Box<dyn MailFromHandler>) {
        self.reject(553, message, handler);
    }
    /// Generic reject.
    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn MailFromHandler>);
    /// Defer the final reply until outbound delivery finishes.
    ///
    /// The session enters [`crate::SmtpSessionState::Delivering`]. Complete later
    /// via [`DeferredDelivery`].
    fn defer(&mut self, resume: Box<dyn MailFromHandler>) -> DeferredDelivery;
    /// Shutting down.
    fn server_shutting_down(&mut self);
}

/// Completes a deferred DATA/BDAT response from another thread (DNS / storage).
pub struct DeferredDelivery {
    handle: hopf_core::ConnHandle,
    slot: std::sync::Arc<std::sync::Mutex<Option<DeferredSlot>>>,
}

pub(crate) struct DeferredSlot {
    pub(crate) resume: Box<dyn MailFromHandler>,
    pub(crate) outcome: Option<DeferredOutcome>,
}

pub(crate) enum DeferredOutcome {
    #[allow(dead_code)]
    Accept {
        queue_id: Option<String>,
    },
    #[allow(dead_code)]
    Reject {
        code: u16,
        text: String,
    },
}

impl DeferredDelivery {
    pub(crate) fn new(
        handle: hopf_core::ConnHandle,
        slot: std::sync::Arc<std::sync::Mutex<Option<DeferredSlot>>>,
    ) -> Self {
        Self { handle, slot }
    }

    /// Send `250` and restore the mail-from handler on the next control turn.
    pub fn accept(self, queue_id: Option<&str>) {
        let queue_id_owned = queue_id.map(|s| s.to_string());
        let reply_bytes = match queue_id_owned.as_deref() {
            Some(id) => crate::server::reply::reply_enhanced(250, "2.0.0", &format!("Queued as {id}")),
            None => crate::server::reply::reply_enhanced(250, "2.0.0", "Message accepted for delivery"),
        };
        if let Some(slot) = self.slot.lock().unwrap().as_mut() {
            slot.outcome = Some(DeferredOutcome::Accept {
                queue_id: queue_id_owned,
            });
        }
        self.handle.send(reply_bytes);
    }

    /// Send a failure reply and restore the mail-from handler on the next control turn.
    pub fn reject(self, code: u16, text: &str) {
        if let Some(slot) = self.slot.lock().unwrap().as_mut() {
            slot.outcome = Some(DeferredOutcome::Reject {
                code,
                text: text.to_string(),
            });
        }
        self.handle.send(crate::server::reply::reply(code, text));
    }

    /// Temporary failure (`450`).
    pub fn reject_temporary(self, message: &str) {
        self.reject(450, message);
    }
}

/// RSET response.
pub trait ResetState {
    /// Accept reset (250) → mail-from.
    fn accept_reset(&mut self, handler: Box<dyn MailFromHandler>);
    /// Shutting down.
    fn server_shutting_down(&mut self);
}
