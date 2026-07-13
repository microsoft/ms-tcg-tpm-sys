// Copyright (C) Microsoft Corporation. All rights reserved.

//! Cancel.c

use serde::Deserialize;
use serde::Serialize;

use super::super::MsTpm185PlatformImpl;

#[derive(Clone, Serialize, Deserialize)]
pub struct CancelState {
    pub flag: bool,
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
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__IsCanceled() -> i32 {
        platform!().is_canceled() as i32
    }

    // NOTE: _plat__SetCancel and _plat__ClearCancel were only ever called by
    // the upstream simulator. Cancellation is now driven from Rust via
    // MsTpm185Platform::set_cancel_flag, which calls the underlying
    // set_cancel()/clear_cancel() methods directly.
}
