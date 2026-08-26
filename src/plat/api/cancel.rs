// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cancel.c

use serde::Deserialize;
use serde::Serialize;

use super::super::MsTpm185PlatformImpl;

#[derive(Clone, Serialize, Deserialize)]
pub struct CancelState {
    flag: bool,
}

impl CancelState {
    pub fn new() -> CancelState {
        CancelState { flag: false }
    }
}

impl MsTpm185PlatformImpl {
    fn is_canceled(&self) -> bool {
        self.state.cancel.flag
    }

    pub fn set_cancel(&mut self) {
        self.state.cancel.flag = true;
    }

    pub fn clear_cancel(&mut self) {
        self.state.cancel.flag = false;
    }
}

mod c_api {
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__IsCanceled")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_is_canceled() -> i32 {
        platform!().is_canceled() as i32
    }
}
