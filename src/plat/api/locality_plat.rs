// Copyright (C) Microsoft Corporation. All rights reserved.

//! LocalityPlat.c

use serde::Deserialize;
use serde::Serialize;

use super::super::MsTpm185PlatformImpl;

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalityState {
    pub locality: u8,
}

impl LocalityState {
    pub fn new() -> LocalityState {
        LocalityState { locality: 0 }
    }
}

impl MsTpm185PlatformImpl {
    fn locality_get(&mut self) -> u8 {
        self.state.locality.locality
    }
}

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__LocalityGet() -> u8 {
        platform!().locality_get()
    }

    // NOTE: _plat__LocalitySet was only ever called by the upstream simulator
    // and is not part of the v1.85 platform interface that the core library uses.
}
