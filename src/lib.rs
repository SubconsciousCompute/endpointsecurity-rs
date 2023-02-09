use crossbeam::channel;

use block::ConcreteBlock;

mod sys {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(unused)]
    #![allow(clippy::all)]
    include!("./sys.rs");
}

#[allow(unused)]
mod bsm;

#[derive(Debug)]
pub enum EsClientCreateError {
    InvalidArgument = 1,
    Internal,
    NotEntitled,
    NotPermited,
    NotPrivileged,
    TooManyClients,
}

impl EsClientCreateError {
    pub fn from_u32(code: u32) -> Option<EsClientCreateError> {
        match code {
            1 => Some(EsClientCreateError::InvalidArgument),
            2 => Some(EsClientCreateError::Internal),
            3 => Some(EsClientCreateError::NotEntitled),
            4 => Some(EsClientCreateError::NotPermited),
            5 => Some(EsClientCreateError::NotPrivileged),
            6 => Some(EsClientCreateError::TooManyClients),
            _ => None,
        }
    }
}

impl std::fmt::Display for EsClientCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_str = match self {
            EsClientCreateError::InvalidArgument => "Error: Invalid Arguments were provided.",
            EsClientCreateError::Internal => "Error: Communication with ES subsystem failed.",
            EsClientCreateError::NotEntitled => "Error: Caller is not properly entitled to connect.",
            EsClientCreateError::NotPermited => "Error: Caller lacks Transparency, Consent, and Control (TCC) approval from the user.",
            EsClientCreateError::NotPrivileged => "Error: Must be run as root",
            EsClientCreateError::TooManyClients => "Error: Too many connected clients",

        };

        f.write_str(err_str)
    }
}

impl std::error::Error for EsClientCreateError {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EsEventType {
    AuthExec,
    AuthOpen,
    AuthKExtLoad,
    AuthMMap,
    AuthMProtect,
    AuthMount,
    AuthRename,
    AuthSignal,
    AuthUnlink,
    NotifyExec = 9,
    NotifyOpen,
    NotifyFork,
    NotifyClose,
    NotifyCreate,
    NotifyExchangeData,
    NotifyExit,
    NotifyGetTask,
    NotifyKExtLoad,
    NotifyKExtUnload,
    NotifyLink,
    NotifyMMap,
    NotifyMProtect,
    NotifyMount,
    NotifyUnmount,
    NotifyIOKitOpen,
    NotifyRename,
    NOtifySetAttrList,
    NotifySetExtAttr,
    NotifySetFlags,
    NotifySetMode,
    NotifySetOwner,
    NotifySIgnal,
    NotifyUnlink,
    NotifyWrite,
    AuthFileProviderMaterialize,
    NotifyFileProviderMaterialize,
    AuthFileProviderUpdate,
    NotifyFileProviderUpdate,
    AuthReadLink,
    NotifyReadLink,
    AuthTruncate,
    NotifyTruncate,
    AuthLink,
    NotifyLookup,
    AuthCreate,
    AuthSetAttrList,
    AuthSetExtAttr,
    AuthSetFlags,
    AuthSetMode,
    AuthSetOwner,
    AuthChdir,
    NotifyChdir,
    AuthGetAttrList,
    NotifyGetAttrList,
    NotifyStat,
    NotifyAccess,
    AuthChroot,
    NotifyChroot,
    AuthUtimes,
    NotifyUtimes,
    AuthClone,
    NotifyClone,
    NotifyFcntl,
    AuthGetExtAttr,
    NotifyGetExtAttr,
    AuthListenExtAttr,
    NotifyListenExtAttr,
    AuthReadDir,
    NotifyReadDir,
    AuthDeleteExtAttr,
    NotifyDeleteExtAttr,
    AuthFsGetPath,
    NotifyFsGetPath,
    NotifyDup,
    AuthSetTime,
    NotifySetTime,
    NotifyUIPCBind,
    AuthUIPCBind,
    NotifyUIPCConnect,
    AuthUIPCConnect,
    AuthExchangeData,
    AuthSetACL,
    NotifySetACL,
    NotifyPTYGrant,
    NotifyPTYClose,
    AuthProcCheck,
    NotifyProcCheck,
    AuthGetTask,
    AuthSearchFs,
    NotifySearchFs,
    AuthFcntl,
    AuthIOKitOpen,
    AuthProcSuspendResume,
    NotifyProcSuspendResume,
    NotifyCsInvalidDate,
    NotifyGetTaskName,
    NotfiyTrace,
    NOtifyRemoteThreadCreate,
    AuthRemount,
    NotifyRemount,
    AuthGetTaskRead,
    NotifyGetTaskRead,
    NotifyGetTaskInspect,
    NotifySetUid,
    NotifySetGid,
    NotifySetEUid,
    NotifySetEGuid,
    NotifySetREUid,
    NotifySetREGuid,
    AuthCopyFile,
    NotifyCopyFile,
    NotifyAuthentication,
    NotifyXPMalwareDetected,
    NotifyXPMalwareRemediated,
    NotifyLWSessionLogin,
    NotifyLWSessionLogout,
    NotifyLWSessionLock,
    NotifyLWSessionUnlock,
    NotifyScreenSharingAttach,
    AuthScreenSharingAttach,
    NotifyOpenSSHLogin,
    NotifyOpenSSHLogout,
    NotifyBTMLaunchItemAdd,
    NotifyBTMLaunchItemRemove,
    Last,
}

#[derive(Debug)]
pub enum EsActionType {
    Auth,
    Notify,
}

#[derive(Debug)]
pub struct EsProcess {
    /// process pid
    pub pid: i32,
    /// Parent pid
    pub ppid: i32,
    /// groupd id
    pub gid: i32,
    audit_token: sys::audit_token_t,
}

impl EsProcess {
    pub fn audit_token(&self) -> sys::audit_token_t {
        self.audit_token
    }
}

impl From<&sys::es_process_t> for EsProcess {
    fn from(value: &sys::es_process_t) -> Self {
        let pid = unsafe { bsm::audit_token_to_pid(value.audit_token) };

        Self {
            audit_token: value.audit_token,
            ppid: value.ppid,
            gid: value.group_id,
            pid,
        }
    }
}

#[derive(Debug)]
pub struct EsMessage {
    pub action: EsActionType,
    pub event: EsEventType,
    pub version: u32,
    pub seq_num: u64,
    pub process: Option<EsProcess>,
    pub thread_id: Option<u64>,
}

impl From<&sys::es_message_t> for EsMessage {
    fn from(message: &sys::es_message_t) -> Self {
        let action = match message.action_type {
            0 => EsActionType::Auth,
            1 => EsActionType::Notify,
            _ => panic!("Useless"),
        };

        // SAFETY: message.event_type will (hopefully) never be out of range
        let eve_type: EsEventType = unsafe { std::mem::transmute(message.event_type) };
        let process = unsafe { message.process.as_ref().map(|process| process.into()) };
        let thread_id = unsafe { message.thread.as_ref().map(|tid| tid.thread_id) };
        Self {
            event: eve_type,
            version: message.version,
            seq_num: message.seq_num,
            action,
            process,
            thread_id,
        }
    }
}

/// Create a new client to connect to Endpoint Security.
pub struct EsClient {
    client: *mut sys::es_client_t,
    subscribed_events: Vec<EsEventType>,
    pub rx: crossbeam::channel::Receiver<EsMessage>,
}

impl EsClient {
    extern "C" fn handler(_c: *mut sys::es_client_t, _m: *const sys::es_message_t) {}

    /// Create a new client that connects to the ES subsystem.
    ///
    /// # Example
    /// ```
    ///     let client = endpointsecurity_rs::EsClient::new();
    ///     assert!(client.is_ok());
    /// ```
    pub fn new() -> anyhow::Result<EsClient> {
        let mut client: *mut sys::es_client_t = std::ptr::null_mut();

        let (tx, rx) = channel::unbounded();

        let handler = ConcreteBlock::new(move |c, msg: *const sys::es_message_t| {
            let message = unsafe { msg.as_ref() };
            if message.is_none() {
                println!("Failed to get message reference");
                return;
            }
            let message = message.unwrap();

            _ = tx.send(message.into());

            // this call is just to infer the types in the closure
            Self::handler(c, msg);
        })
        .copy();

        if let Some(err) = EsClientCreateError::from_u32(unsafe {
            sys::es_new_client(
                &mut client as _,
                &*handler as *const block::Block<_, _> as *mut std::ffi::c_void,
            )
        }) {
            anyhow::bail!(err)
        }

        Ok(EsClient {
            client,
            subscribed_events: vec![],
            rx,
        })
    }

    /// Add a new event to subscribe
    pub fn add_event(&mut self, event: EsEventType) -> &mut Self {
        self.subscribed_events.push(event);
        self
    }

    /// Subscribe to all the events added using [Self::add_event]
    pub fn subscribe(&self) {
        let mut event_ids = vec![];
        for evt in &self.subscribed_events {
            event_ids.push(*evt as sys::es_event_type_t)
        }

        if unsafe {
            sys::es_subscribe(self.client as _, event_ids.as_ptr(), event_ids.len() as u32)
        } != 0
        {
            panic!("Error: Failed to subscribe");
        }
    }

    /// returns true if call to unsubscribe is successful, otherwise false/
    pub fn unsubscribe_all(&self) -> bool {
        (unsafe { sys::es_unsubscribe_all(self.client) } == 0)
    }

    /// returns true if call to unsubscribe is successful, otherwise false/
    pub fn unsubscribe(&mut self, event: EsEventType) -> bool {
        if let Some(idx) = self.subscribed_events.iter().position(|eve| *eve == event) {
            self.subscribed_events.swap_remove(idx);
        }

        let events = vec![event as u32];

        (unsafe { sys::es_unsubscribe(self.client, events.as_ptr(), events.len() as u32) } == 0)
    }

    /// This function blocks
    pub fn recv_msg(&self) -> Result<EsMessage, channel::RecvError> {
        self.rx.recv()
    }

    /// This function doesn't block
    pub fn try_recv_msg(&self) -> Result<EsMessage, channel::TryRecvError> {
        self.rx.try_recv()
    }
}

impl Drop for EsClient {
    fn drop(&mut self) {
        if unsafe { sys::es_delete_client(self.client) } != 0 {
            println!("Failed to delete client");
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    pub fn test_new_es_client() {
        let client = crate::EsClient::new();
        assert!(client.is_ok());
    }
}
