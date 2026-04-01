#![allow(deprecated)] // aes-gcm uses generic-array with deprecated from_slice/as_slice

pub mod attestation;
pub mod ecies;
pub mod error;
#[cfg(not(target_env = "musl"))]
pub mod provider;
pub mod sealing;
pub mod snp_report;

pub use error::SealError;

// v2 hardware-derived key sealing (MSG_KEY_REQ / SNP_GET_DERIVED_KEY)
// Only available on glibc targets (ioctl interface has libc type differences on musl)
#[cfg(not(target_env = "musl"))]
pub use provider::{
    get_derived_key, FIELD_FAMILY_ID, FIELD_GUEST_POLICY, FIELD_GUEST_SVN, FIELD_IMAGE_ID,
    FIELD_MEASUREMENT, FIELD_TCB_VERSION, SAFE_FIELD_SELECT,
};
#[cfg(not(target_env = "musl"))]
pub use sealing::{parse_v2_header, seal_derived, unseal_derived};
