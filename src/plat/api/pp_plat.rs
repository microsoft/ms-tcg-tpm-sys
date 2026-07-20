// Copyright (C) Microsoft Corporation. All rights reserved.

//! PPPlat.c

// TODO: model physical presence using `PlaformCallbacks`?

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__PhysicalPresenceAsserted() -> i32 {
        false as i32
    }
}
