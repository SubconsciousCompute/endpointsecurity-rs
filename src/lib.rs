//! endpointsecurity-rs
//!
//! This crate provides safe bindings to the the [OSX Endpoint Security API](https://developer.apple.com/documentation/endpointsecurity).

//! This crates operators over crossbeam channels where you can subscribe to the events you're interested in.
//!
//! Not all events are supported. If you want a event to be added, open an issue on our [github](https://github.com/SubconsciousCompute/endpointsecurity-rs) repo.
//!

use std::{error::Error, fmt::Display};

use block::ConcreteBlock;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

mod sys {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(unused)]
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/ep_sys.rs"));
}

#[allow(unused)]
mod bsm;

/// An EsClient instance
pub struct Client {
    client: *mut sys::es_client_t,
}

macro_rules! handle_es_return {
    ($ex: expr, $s: expr, $f: expr) => {
        match $ex {
            sys::es_return_t_ES_RETURN_SUCCESS => $s,
            _ => $f,
        }
    };
}

#[derive(Debug)]
pub struct EsNotReachable;

impl Error for EsNotReachable {}

impl Display for EsNotReachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("endpointsecurity subsystem was not reachable.")
    }
}

impl Client {
    pub fn new() -> Result<Self, ClientErr> {
        let mut client = std::ptr::null_mut();

        let handler = ConcreteBlock::new(
            move |c: *mut sys::es_client_t, msg: *const sys::es_message_t| {
                println!("some event");
            },
        )
        .copy();

        unsafe {
            match sys::es_new_client(
                &mut client as _,
                &*handler as *const block::Block<_, _> as *mut std::ffi::c_void,
            ) {
                0 => Ok(Client { client }),
                code @ _ => {
                    if (1..=7).contains(&code) {
                        Err(FromPrimitive::from_u32(code).unwrap())
                    } else {
                        Err(ClientErr::UnknownErr)
                    }
                }
            }
        }
    }

    pub fn subscribe(&self, events: &[EventType]) -> Result<(), EsNotReachable> {
        if sys::es_return_t_ES_RETURN_ERROR
            == unsafe { sys::es_subscribe(self.client, events.as_ptr() as _, events.len() as u32) }
        {
            Err(EsNotReachable)
        } else {
            Ok(())
        }
    }

    /// returns all the events subscribed to
    pub fn subscriptions(&self) -> Result<Vec<EventType>, EsNotReachable> {
        let mut events: *mut EventType = std::ptr::null_mut();
        let mut count = 0;

        if sys::es_return_t_ES_RETURN_SUCCESS
            == unsafe {
                sys::es_subscriptions(self.client, &mut count as _, &mut events as *mut _ as _)
            }
        {
            let ets = unsafe { std::slice::from_raw_parts(events, count) }.to_vec();
            unsafe {
                libc::free(events as _);
            }

            Ok(ets)
        } else {
            Err(EsNotReachable)
        }
    }

    /// unsubscribe from all the events subscribed to.
    pub fn unsubscribe(&self) {
        handle_es_return!(
            unsafe { sys::es_unsubscribe_all(self.client) },
            tracing::debug!("endpointsecurity: unsubscribed from all events"),
            tracing::error!(
                "endpointsecurity: failed to unsubcribe from all events. Cannot reach ES server."
            )
        )
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.client.is_null() {
            return;
        }

        // unsubscribe from all subscribed events
        self.unsubscribe();

        match unsafe { sys::es_delete_client(self.client) } {
            sys::es_return_t_ES_RETURN_SUCCESS => {
                tracing::debug!("endpointsecurity: deleted client instance");
            }
            _ => {
                tracing::error!("endpointsecurity: Failed to delete es client")
            }
        }
    }
}

/// Possible errors returned if [EsClient::new()] fails
#[derive(Debug, FromPrimitive)]
pub enum ClientErr {
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

    /// Unknown Err returned by `es_new_client`
    UnknownErr = 100,
}

impl std::fmt::Display for ClientErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_str = match self {
            ClientErr::InvalidArgument => "Error: Invalid Arguments were provided.",
            ClientErr::Internal => "Error: Communication with ES subsystem failed.",
            ClientErr::NotEntitled => "Error: Caller is not properly entitled to connect.",
            ClientErr::NotPermited => "Error: Caller lacks Transparency, Consent, and Control (TCC) approval from the user.",
            ClientErr::NotPrivileged => "Error: Must be run as root",
            ClientErr::TooManyClients => "Error: Too many connected clients",
            ClientErr::UnknownErr => "Error: `es_new_client` returned unknown err. This is probably a bug. Please report issue on github.",
        };

        f.write_str(err_str)
    }
}

impl std::error::Error for ClientErr {}

/// All the events supported by Endpoint Security, see [more](https://developer.apple.com/documentation/endpointsecurity/event_types)
///
/// *README*: While all events are supported by the crate, only few have [EsEventData] types.
/// If one of the event your interested in is missing, please send us a PR or open an issue on github.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EventType {
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

#[cfg(test)]
mod tests {

    #[test]
    pub fn test_new_es_client() {}
}
