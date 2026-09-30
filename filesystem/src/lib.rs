#![allow(unexpected_cfgs)]

pub mod ext4;
#[cfg(target_os = "mochios")]
pub mod platform_storage;
pub mod storage;
