//! endpointsecurity-rs
//!
//! This crate provides safe bindings to the the [OSX Endpoint Security API](https://developer.apple.com/documentation/endpointsecurity).

//! This crates operators over crossbeam channels where you can subscribe to the events you're interested in.
//!
//! Not all events are supported. If you want a event to be added, open an issue on our [github](https://github.com/SubconsciousCompute/endpointsecurity-rs) repo.
//!

use std::ffi::CStr;

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

macro_rules! es_string_to_string {
    ($ex: expr) => {
        CStr::from_ptr($ex).to_string_lossy().to_string()
    };
}

macro_rules! es_string_to_opt_string {
    ($ex: expr) => {
        if $ex.is_null() {
            None
        } else {
            Some(CStr::from_ptr($ex).to_string_lossy().to_string())
        }
    };
}

/// Possible errors returned if [EsClient::new()] fails
#[derive(Debug)]
pub enum EsClientCreateError {
    /// Arguments to [EsClient] are invalid
    InvalidArgument = 1,
    /// Internal Endpoint Security error
    Internal,
    /// Executable isn't signed with required entitlements
    NotEntitled,
    /// Operation not permitted
    NotPermited,
    /// Executable didn't run as root
    NotPrivileged,
    /// Too many clients are connected to Endpoint Security
    TooManyClients,
}

impl EsClientCreateError {
    fn from_u32(code: u32) -> Option<EsClientCreateError> {
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

/// All the events supported by Endpoint Security, see [more](https://developer.apple.com/documentation/endpointsecurity/event_types)
///
/// *README*: While all events are supported by the crate, only few have [EsEventData] types.
/// If one of the event your interested in is missing, please send us a PR or open an issue on github.
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
    NotifyExec,
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
    NotifySignal,
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
    NotifyRemoteThreadCreate,
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

/// The event type
#[derive(Debug, PartialEq)]
pub enum EsActionType {
    Auth,
    Notify,
}

#[repr(u32)]
pub enum EsMutePath {
    Prefix,
    Literal,
}

/// Info returned by Notify/Auth Rename events.
#[derive(Debug)]
pub struct EsRename {
    /// source file to rename
    pub source: EsFile,
    /// destination of renamed file if filename with same name already exists
    pub destination_existing: Option<EsFile>,
    /// destination of renamed file if filename with same name doesn't exists
    pub destintaion_newpath: Option<(EsFile, String)>,
}

/// Status returned by Es on NotifySSH events
#[derive(Debug)]
pub enum EsSSHLoginResult {
    LoginExceedMaxTries,
    LoginRootDenied,
    AuthSuccess,
    FailNone,
    FailPasswd,
    FailKBDInt,
    FailPubKey,
    FailHostBased,
    FailGSSApi,
    InvalidUser,
}

#[derive(Debug)]
pub enum EsAddressType {
    None,
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
    NamedSocket(String),
}

impl EsAddressType {
    fn parse(str: &sys::es_string_token_t, ty: u32) -> Self {
        if ty == 0 {
            EsAddressType::None
        } else {
            let addr_str = unsafe {
                std::ffi::CStr::from_ptr(str.data)
                    .to_string_lossy()
                    .to_string()
            };
            match ty {
                1 => EsAddressType::Ipv4(addr_str.parse().unwrap()),
                2 => EsAddressType::Ipv6(addr_str.parse().unwrap()),
                _ => panic!("Shouldn't reach here"),
            }
        }
    }
}

#[derive(Debug)]
pub struct EsSshLogin {
    pub success: bool,
    pub result: EsSSHLoginResult,
    pub source_address: EsAddressType,
    pub username: String,
    pub uid: Option<u32>,
}

impl From<&sys::es_event_openssh_login_t> for EsSshLogin {
    fn from(value: &sys::es_event_openssh_login_t) -> Self {
        let username = unsafe {
            std::ffi::CStr::from_ptr(value.username.data)
                .to_string_lossy()
                .to_string()
        };

        let result = match value.result_type {
            0 => EsSSHLoginResult::LoginExceedMaxTries,
            1 => EsSSHLoginResult::LoginRootDenied,
            2 => EsSSHLoginResult::AuthSuccess,
            3 => EsSSHLoginResult::FailNone,
            4 => EsSSHLoginResult::FailPasswd,
            5 => EsSSHLoginResult::FailKBDInt,
            6 => EsSSHLoginResult::FailPubKey,
            7 => EsSSHLoginResult::FailHostBased,
            8 => EsSSHLoginResult::FailGSSApi,
            9 => EsSSHLoginResult::InvalidUser,
            _ => panic!("Should never reach this case"),
        };

        Self {
            success: value.success,
            username,
            uid: (if value.has_uid {
                unsafe { Some(value.uid.uid) }
            } else {
                None
            }),
            result,
            source_address: EsAddressType::parse(&value.source_address, value.source_address_type),
        }
    }
}

#[derive(Debug)]
pub struct EsSSHLogout {
    pub source_address: EsAddressType,
    pub username: String,
    pub uid: u32,
}

impl From<&sys::es_event_openssh_logout_t> for EsSSHLogout {
    fn from(value: &sys::es_event_openssh_logout_t) -> Self {
        Self {
            username: unsafe {
                std::ffi::CStr::from_ptr(value.username.data)
                    .to_string_lossy()
                    .to_string()
            },
            uid: value.uid,
            source_address: EsAddressType::parse(&value.source_address, value.source_address_type),
        }
    }
}

#[derive(Debug)]
pub struct EsUnlinkFile {
    pub parent_dir: EsFile,
    pub target: EsFile,
}

impl From<sys::es_event_unlink_t> for EsUnlinkFile {
    fn from(value: sys::es_event_unlink_t) -> Self {
        unsafe {
            Self {
                parent_dir: value.parent_dir.as_ref().unwrap().into(),
                target: value.target.as_ref().unwrap().into(),
            }
        }
    }
}

#[derive(Debug)]
pub struct EsCopyFile {
    pub source: Option<EsFile>,
    pub target_file: Option<EsFile>,
    pub target_dir: Option<EsFile>,
    pub target_name: String,
    pub mode: u16,
    pub flags: i32,
}

impl From<sys::es_event_copyfile_t> for EsCopyFile {
    fn from(value: sys::es_event_copyfile_t) -> Self {
        unsafe {
            Self {
                source: value.source.as_ref().map(|src| src.into()),
                target_file: value.target_file.as_ref().map(|tar| tar.into()),
                target_dir: value.target_dir.as_ref().map(|t_dir| t_dir.into()),
                target_name: CStr::from_ptr(value.target_name.data)
                    .to_string_lossy()
                    .to_string(),
                mode: value.mode,
                flags: value.flags,
            }
        }
    }
}

#[derive(Debug)]
pub enum EsDestination {
    ExistingFile(EsFile),
    NewPath(EsCreateMetadata),
}

#[derive(Debug)]
pub struct EsCreateMetadata {
    pub dir: EsFile,
    pub filename: String,
    pub mode: u16,
}

#[derive(Debug)]
pub struct EsCreate {
    pub destination: EsDestination,
}

impl From<sys::es_event_create_t> for EsCreate {
    fn from(value: sys::es_event_create_t) -> Self {
        let destination = match value.destination_type {
            0 => unsafe {
                EsDestination::ExistingFile(
                    value.destination.existing_file.as_ref().unwrap().into(),
                )
            },
            1 => {
                let new_path = unsafe { value.destination.new_path };
                unsafe {
                    EsDestination::NewPath(EsCreateMetadata {
                        dir: new_path.dir.as_ref().unwrap().into(),
                        filename: es_string_to_string!(new_path.filename.data),
                        mode: new_path.mode,
                    })
                }
            }
            _ => {
                panic!("EsCreate: destination type out of range")
            }
        };
        Self { destination }
    }
}

#[derive(Debug)]
pub struct EsClone {
    pub source: EsFile,
    pub target_dir: EsFile,
    pub name: String,
}

impl From<sys::es_event_clone_t> for EsClone {
    fn from(value: sys::es_event_clone_t) -> Self {
        Self {
            source: unsafe { value.source.as_ref().unwrap().into() },
            target_dir: unsafe { value.target_dir.as_ref().unwrap().into() },
            name: unsafe { es_string_to_string!(value.target_name.data) },
        }
    }
}

#[derive(Debug)]
pub struct EsMMap {
    pub protection: i32,
    pub max_protection: i32,
    pub flags: i32,
    pub file_pos: u64,
    pub source: EsFile,
}

impl From<sys::es_event_mmap_t> for EsMMap {
    fn from(value: sys::es_event_mmap_t) -> Self {
        Self {
            protection: value.protection,
            max_protection: value.max_protection,
            flags: value.flags,
            file_pos: value.file_pos,
            source: unsafe { value.source.as_ref() }.unwrap().into(),
        }
    }
}

#[derive(Debug)]
pub struct EsScreenSharingAttach {
    pub success: bool,
    pub source_address: EsAddressType,
    pub viewer_appleid: Option<String>,
    pub authentication_type: Option<String>,
    pub session_username: Option<String>,
    pub existing_session: bool,
    pub graphical_session_id: u32,
}

impl From<sys::es_event_screensharing_attach_t> for EsScreenSharingAttach {
    fn from(value: sys::es_event_screensharing_attach_t) -> Self {
        Self {
            success: value.success,
            source_address: EsAddressType::parse(&value.source_address, value.source_address_type),
            viewer_appleid: unsafe { es_string_to_opt_string!(value.viewer_appleid.data) },
            authentication_type: unsafe {
                es_string_to_opt_string!(value.authentication_type.data)
            },
            existing_session: value.existing_session,
            graphical_session_id: value.graphical_session_id,
            session_username: unsafe { es_string_to_opt_string!(value.viewer_appleid.data) },
        }
    }
}

#[derive(Debug)]
pub enum EsEventData {
    AuthOpen(EsFile),
    AuthRename(EsRename),
    AuthUnlink(EsUnlinkFile),
    AuthReadDir(EsFile),
    AuthChroot(EsFile),
    AuthCopyFile(EsCopyFile),
    NotifyCopyFile(EsCopyFile),

    NotifyClone(EsClone),
    AuthClone(EsClone),

    NotifyMMap(EsMMap),
    AuthMMap(EsMMap),

    NotifyExit(i32),

    NotifyOpen(EsFile),
    NotifyExec(EsProcess),
    NotifyWrite(EsFile),
    NotifyRename(EsRename),
    NotifyReadDir(EsFile),
    NotifyChroot(EsFile),
    /// 2nd argument is true if the file was modified
    NotifyClose((EsFile, bool)),
    NotifyOpenSSHLogin(EsSshLogin),
    NotifyOpenSSHLogout(EsSSHLogout),
    NotifyLWSessionLock(EsLWSession),
    NotifyLWSessionUnlock(EsLWSession),
    NotifyLWSessionLogin(EsLWSession),
    NotifyLWSessionLogout(EsLWSession),
}

impl From<sys::es_event_rename_t> for EsRename {
    fn from(value: sys::es_event_rename_t) -> Self {
        let source = unsafe { value.source.as_ref().unwrap().into() };

        let mut rename_info = Self {
            source,
            destination_existing: None,
            destintaion_newpath: None,
        };

        if value.destination_type == 0 {
            rename_info.destination_existing = unsafe {
                value
                    .destination
                    .existing_file
                    .as_ref()
                    .map(|file| file.into())
            };
        } else {
            rename_info.destintaion_newpath = Some((
                unsafe { value.destination.new_path.dir.as_ref().unwrap().into() },
                unsafe {
                    std::ffi::CStr::from_ptr(value.destination.new_path.filename.data)
                        .to_string_lossy()
                        .to_string()
                },
            ));
        }

        rename_info
    }
}

#[derive(Debug)]
pub struct EsFile {
    pub path: String,
    pub path_truncated: bool,
}

impl From<&sys::es_file_t> for EsFile {
    fn from(file: &sys::es_file_t) -> Self {
        let path = unsafe { std::ffi::CStr::from_ptr(file.path.data) }
            .to_string_lossy()
            .to_string();

        Self {
            path,
            path_truncated: file.path_truncated,
        }
    }
}

#[derive(Debug)]
pub struct EsProcess {
    /// process pid
    pub pid: i32,
    /// Parent pid
    pub ppid: i32,
    /// groupd id
    pub gid: i32,
    pub exe: EsFile,
    audit_token: sys::audit_token_t,
}

impl EsProcess {
    pub fn audit_token(&self) -> sys::audit_token_t {
        self.audit_token
    }

    pub fn mute(&self, client: &EsClient) {
        unsafe { sys::es_mute_process(client.client as _, &self.audit_token as _) };
    }
}

impl From<&sys::es_process_t> for EsProcess {
    fn from(value: &sys::es_process_t) -> Self {
        let pid = unsafe { bsm::audit_token_to_pid(value.audit_token) };

        Self {
            audit_token: value.audit_token,
            ppid: value.ppid,
            gid: value.group_id,
            exe: unsafe { value.executable.as_ref().unwrap().into() },
            pid,
        }
    }
}

#[derive(Debug)]
pub struct EsLWSession {
    pub graphical_session_id: u32,
    pub username: String,
}

impl EsLWSession {
    fn from_es_type(id: u32, str: *const i8) -> Self {
        Self {
            graphical_session_id: id,
            username: unsafe { CStr::from_ptr(str).to_string_lossy().to_string() },
        }
    }
}

pub struct EsUser {
    pub uid: u32,
    pub username: String,
}

pub struct EsLogin {
    pub success: bool,
    pub err: Option<String>,
    pub user: EsUser,
}

impl From<&sys::es_event_login_login_t> for EsLogin {
    fn from(value: &sys::es_event_login_login_t) -> Self {
        Self {
            success: value.success,
            err: if !value.success {
                Some(unsafe { es_string_to_string!(value.failure_message.data) })
            } else {
                None
            },
            user: EsUser {
                uid: unsafe { value.uid.uid },
                username: unsafe { es_string_to_string!(value.username.data) },
            },
        }
    }
}

#[derive(Debug)]
pub struct EsMessage {
    pub action: EsActionType,
    pub event: EsEventType,
    pub event_data: Option<EsEventData>,
    pub version: u32,
    pub seq_num: u64,
    pub process: Option<EsProcess>,
    pub thread_id: Option<u64>,
    message_ptr: *const sys::es_message_t,
}

impl EsMessage {
    pub fn allow(&self, client: &EsClient) {
        if self.action == EsActionType::Auth {
            assert!(
                unsafe { sys::es_respond_auth_result(client.client, self.message_ptr, 0, true) }
                    == 0
            );
        }
    }

    pub fn deny(&self, client: &EsClient) {
        if self.action == EsActionType::Auth {
            assert!(
                unsafe { sys::es_respond_auth_result(client.client, self.message_ptr, 1, true) }
                    == 0
            );
        }
    }
}

impl Drop for EsMessage {
    fn drop(&mut self) {
        unsafe { sys::es_release_message(self.message_ptr) };
    }
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

        // unsafe { message.event.screensharing_attach.as_ref().unwrap() }

        let eve = match eve_type {
            EsEventType::AuthOpen => unsafe {
                message
                    .event
                    .open
                    .file
                    .as_ref()
                    .map(|file| EsEventData::AuthOpen(file.into()))
            },
            EsEventType::AuthRename => Some(EsEventData::AuthRename(unsafe {
                message.event.rename.into()
            })),
            EsEventType::AuthUnlink => Some(EsEventData::AuthUnlink(unsafe {
                message.event.unlink.into()
            })),
            EsEventType::AuthReadDir => unsafe {
                message
                    .event
                    .readdir
                    .target
                    .as_ref()
                    .map(|readdir| EsEventData::AuthReadDir(readdir.into()))
            },
            EsEventType::AuthChroot => unsafe {
                message
                    .event
                    .chroot
                    .target
                    .as_ref()
                    .map(|chroot| EsEventData::AuthChroot(chroot.into()))
            },
            EsEventType::NotifyChroot => unsafe {
                message
                    .event
                    .chroot
                    .target
                    .as_ref()
                    .map(|chroot| EsEventData::NotifyChroot(chroot.into()))
            },
            EsEventType::NotifyExec => unsafe {
                message
                    .event
                    .exec
                    .target
                    .as_ref()
                    .map(|tar| EsEventData::NotifyExec(tar.into()))
            },
            EsEventType::NotifyOpen => unsafe {
                message
                    .event
                    .open
                    .file
                    .as_ref()
                    .map(|file| EsEventData::NotifyOpen(file.into()))
            },
            EsEventType::NotifyWrite => unsafe {
                message
                    .event
                    .write
                    .target
                    .as_ref()
                    .map(|target| EsEventData::NotifyWrite(target.into()))
            },
            EsEventType::NotifyRename => Some(EsEventData::NotifyRename(unsafe {
                message.event.rename.into()
            })),
            EsEventType::NotifyClose => Some(EsEventData::NotifyClose((
                unsafe { message.event.close.target.as_ref().unwrap().into() },
                unsafe { message.event.close.modified },
            ))),
            EsEventType::NotifyReadDir => unsafe {
                message
                    .event
                    .readdir
                    .target
                    .as_ref()
                    .map(|readdir| EsEventData::NotifyReadDir(readdir.into()))
            },
            EsEventType::NotifyOpenSSHLogin => unsafe {
                message
                    .event
                    .openssh_login
                    .as_ref()
                    .map(|login| EsEventData::NotifyOpenSSHLogin(login.into()))
            },
            EsEventType::NotifyOpenSSHLogout => unsafe {
                message
                    .event
                    .openssh_logout
                    .as_ref()
                    .map(|logout| EsEventData::NotifyOpenSSHLogout(logout.into()))
            },
            EsEventType::NotifyLWSessionLock => unsafe {
                message.event.lw_session_lock.as_ref().map(|session| {
                    EsEventData::NotifyLWSessionLock(EsLWSession::from_es_type(
                        session.graphical_session_id,
                        session.username.data,
                    ))
                })
            },
            EsEventType::NotifyLWSessionLogin => unsafe {
                message.event.lw_session_login.as_ref().map(|session| {
                    EsEventData::NotifyLWSessionLogin(EsLWSession::from_es_type(
                        session.graphical_session_id,
                        session.username.data,
                    ))
                })
            },
            EsEventType::NotifyLWSessionLogout => unsafe {
                message.event.lw_session_logout.as_ref().map(|session| {
                    EsEventData::NotifyLWSessionLogout(EsLWSession::from_es_type(
                        session.graphical_session_id,
                        session.username.data,
                    ))
                })
            },
            EsEventType::NotifyLWSessionUnlock => unsafe {
                message.event.lw_session_unlock.as_ref().map(|session| {
                    EsEventData::NotifyLWSessionUnlock(EsLWSession::from_es_type(
                        session.graphical_session_id,
                        session.username.data,
                    ))
                })
            },
            EsEventType::AuthCopyFile => unsafe {
                Some(EsEventData::AuthCopyFile(message.event.copyfile.into()))
            },
            EsEventType::NotifyCopyFile => unsafe {
                Some(EsEventData::NotifyCopyFile(message.event.copyfile.into()))
            },
            EsEventType::NotifyClone => unsafe {
                Some(EsEventData::AuthClone(message.event.clone.into()))
            },
            EsEventType::AuthClone => unsafe {
                Some(EsEventData::AuthClone(message.event.clone.into()))
            },
            EsEventType::NotifyMMap => unsafe {
                Some(EsEventData::NotifyMMap(message.event.mmap.into()))
            },
            EsEventType::AuthMMap => unsafe {
                Some(EsEventData::AuthMMap(message.event.mmap.into()))
            },
            EsEventType::NotifyExit => unsafe {
                Some(EsEventData::NotifyExit(message.event.exit.stat))
            },
            _ => None,
        };

        unsafe { sys::es_retain_message(message as _) }

        Self {
            event: eve_type,
            event_data: eve,
            version: message.version,
            seq_num: message.seq_num,
            message_ptr: message as _,
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
            assert!(msg as usize == message as *const _ as usize);

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
        if !self.subscribed_events.contains(&event) {
            self.subscribed_events.push(event);
        }
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

    /// returns true if call to unsubscribe is successful, otherwise false
    pub fn unsubscribe_all(&self) -> bool {
        (unsafe { sys::es_unsubscribe_all(self.client) } == 0)
    }

    /// returns true if call to unsubscribe is successful, otherwise false/
    pub fn unsubscribe(&mut self, event: EsEventType) -> bool {
        if let Some(idx) = self.subscribed_events.iter().position(|eve| *eve == event) {
            self.subscribed_events.swap_remove(idx);
        } else {
            return false;
        }

        let events = vec![event as u32];

        (unsafe { sys::es_unsubscribe(self.client, events.as_ptr(), events.len() as u32) } == 0)
    }

    /// Get the events that the user subscribed to. Returns `None` on error
    pub fn subscriptions(&self) -> Option<Vec<EsEventType>> {
        let mut count = 0;
        let mut eves: *mut EsEventType = core::ptr::null_mut();
        if unsafe {
            sys::es_subscriptions(
                self.client,
                &mut count,
                &mut eves as *mut *mut _ as *mut *mut u32,
            )
        } != 0
        {
            None
        } else {
            let events = unsafe { std::slice::from_raw_parts(eves, count) }.to_vec();

            // im not sure if this is the correct way to free
            extern "C" {
                fn free(ptr: *mut std::ffi::c_void);
            }
            unsafe { free(eves as _) };

            Some(events)
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

    /// Suppresses events from executables that match a given path.
    /// Returns `true` if muting was succesful.
    pub fn mute_path(&self, path: &std::path::Path, ty: EsMutePath) -> bool {
        (unsafe { sys::es_mute_path(self.client, path.to_string_lossy().as_ptr() as _, ty as u32) }
            == 0)
    }

    /// Restores event delivery from a previously-muted path.
    /// Returns `true` if muting was succesful.
    pub fn unmute_path(&self, path: &std::path::Path, ty: EsMutePath) -> bool {
        (unsafe {
            sys::es_unmute_path(self.client, path.to_string_lossy().as_ptr() as _, ty as u32)
        } == 0)
    }

    /// Restores event delivery of a subset of events from a previously-muted path.
    pub fn unmute_path_events(
        &self,
        path: &std::path::Path,
        ty: EsMutePath,
        events: &[EsEventType],
    ) -> bool {
        let events: Vec<_> = events.iter().map(|event| *event as u32).collect();

        (unsafe {
            sys::es_unmute_path_events(
                self.client,
                path.to_string_lossy().as_ptr() as _,
                ty as u32,
                events.as_ptr(),
                events.len(),
            )
        } == 0)
    }

    /// Restores event delivery from previously-muted paths.
    pub fn unmute_all_paths(&self) -> bool {
        (unsafe { sys::es_unmute_all_paths(self.client) } == 0)
    }

    /// Deletes the client
    pub fn destroy_client(self) {}
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
