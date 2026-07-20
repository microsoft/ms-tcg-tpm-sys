// Copyright (C) Microsoft Corporation. All rights reserved.

//! LocalityPlat.c

use serde::Deserialize;
use serde::Serialize;

use super::super::MsTpm185PlatformImpl;

/// The locality assigned by the platform to a TPM command.
///
/// The TCG TPM 2.0 Library Specification defines localities 0 through 4 and
/// extended localities 32 through 255. Values 5 through 31 are not selectable.
/// The meaning of a locality is platform-specific; the descriptions of
/// [`Locality::L0`] through [`Locality::L4`] include the nominal associations
/// from the TCG PC Client Platform TPM Profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Locality {
    /// Locality 0 (`TPM_LOC_ZERO`).
    ///
    /// This is the default locality. The PC Client profile nominally associates
    /// it with the Static Root of Trust for Measurement, its chain of trust,
    /// and its environment.
    #[default]
    L0,
    /// Locality 1 (`TPM_LOC_ONE`).
    ///
    /// The PC Client profile nominally associates it with an environment for
    /// use by the Dynamic OS.
    L1,
    /// Locality 2 (`TPM_LOC_TWO`).
    ///
    /// The PC Client profile nominally associates it with the Dynamically
    /// Launched OS runtime environment.
    L2,
    /// Locality 3 (`TPM_LOC_THREE`).
    ///
    /// The PC Client profile reserves it for optional, implementation-defined
    /// auxiliary components.
    L3,
    /// Locality 4 (`TPM_LOC_FOUR`).
    ///
    /// The PC Client profile nominally associates it with trusted hardware or
    /// CPU microcode establishing the Dynamic Root of Trust for Measurement.
    L4,
    /// An extended locality in the range 32 through 255.
    Extended(ExtendedLocality),
}

/// A validated extended TPM locality in the range 32 through 255.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedLocality(u8);

impl TryFrom<u8> for ExtendedLocality {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value >= 32 {
            Ok(Self(value))
        } else {
            Err(())
        }
    }
}

impl TryFrom<u8> for Locality {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Locality::L0),
            1 => Ok(Locality::L1),
            2 => Ok(Locality::L2),
            3 => Ok(Locality::L3),
            4 => Ok(Locality::L4),
            _ => ExtendedLocality::try_from(value).map(Locality::Extended),
        }
    }
}

impl From<ExtendedLocality> for Locality {
    fn from(locality: ExtendedLocality) -> Self {
        Self::Extended(locality)
    }
}

impl From<ExtendedLocality> for u8 {
    fn from(locality: ExtendedLocality) -> Self {
        locality.0
    }
}

impl From<Locality> for u8 {
    fn from(locality: Locality) -> Self {
        match locality {
            Locality::L0 => 0,
            Locality::L1 => 1,
            Locality::L2 => 2,
            Locality::L3 => 3,
            Locality::L4 => 4,
            Locality::Extended(ExtendedLocality(value)) => value,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalityState {
    locality: u8,
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

    pub(crate) fn locality_set(&mut self, locality: Locality) {
        self.state.locality.locality = locality.into();
    }
}

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__LocalityGet() -> u8 {
        platform!().locality_get()
    }
}
