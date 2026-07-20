// Copyright (C) Microsoft Corporation. All rights reserved.

macro_rules! platform {
    () => {
        crate::plat::PLATFORM
            .try_lock()
            .expect("TPM platform is neither reentrant or multithread capable!")
            .as_mut()
            .expect("called platform function prior to initialization")
    };
}

pub mod cancel;
pub mod clock;
pub mod entropy;
pub mod failure;
pub mod init;
pub mod locality_plat;
pub mod nv_virtual;
pub mod nvmem;
pub mod pcr;
pub mod power_plat;
pub mod pp_plat;
pub mod self_test;
pub mod vendor_info;
