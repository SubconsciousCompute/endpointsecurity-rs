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

#[derive(Copy, Clone, Debug)]
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
pub struct EsMessage {
    pub event: EsEventType,
}

pub struct EsClient {
    client: *mut sys::es_client_t,
    subscribed_events: Vec<EsEventType>,
    pub rx: crossbeam::channel::Receiver<EsMessage>,
}

impl EsClient {
    extern "C" fn handler(_c: *mut sys::es_client_t, _m: *const sys::es_message_t) {}

    /// Create a new client to the ES subsystem
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

            // SAFETY: message.event_type will (hopefully) never be out of range
            let eve_type: EsEventType = unsafe { std::mem::transmute(message.event_type) };

            _ = tx.send(EsMessage { event: eve_type });

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

    /// This function blocks
    pub fn recv_msg(&self) -> Result<EsMessage, channel::RecvError> {
        self.rx.recv()
    }

    /// This function doesn't block
    pub fn try_recv_msg(&self) -> Result<EsMessage, channel::TryRecvError> {
        self.rx.try_recv()
    }
}
