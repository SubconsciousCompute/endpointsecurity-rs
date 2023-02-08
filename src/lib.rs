#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use block::ConcreteBlock;

mod sys {
    include!("./sys.rs");
}
pub struct EsClient {
    client: *mut sys::es_client_t,
}

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

impl EsClient {
    extern "C" fn handler(c: *mut sys::es_client_t, m: *const sys::es_message_t) {}

    /// Create a new client to the ES subsystem
    pub fn new() -> anyhow::Result<EsClient> {
        let mut client: *mut sys::es_client_t = std::ptr::null_mut();

        let handler = ConcreteBlock::new(move |c, m| {
            Self::handler(c, m);
        })
        .copy();

        let res = unsafe {
            sys::es_new_client(
                &mut client as _,
                &*handler as *const block::Block<_, _> as *mut std::ffi::c_void,
            )
        };

        if let Some(err) = EsClientCreateError::from_u32(res) {
            anyhow::bail!(err)
        }

        Ok(EsClient { client })
    }
}
