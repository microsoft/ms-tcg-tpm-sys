// Copyright (C) Microsoft Corporation. All rights reserved.

//! Clock.c

use std::convert::TryInto;

use serde::Deserialize;
use serde::Serialize;

use super::super::MsTpm185PlatformImpl;

/// CLOCK_NOMINAL is the number of hardware ticks per ms. A value of 30000 means
/// that the nominal clock rate used to drive the hardware clock is 30 MHz. The
/// adjustment rates are used to determine the conversion of the hardware ticks to
/// internal hardware clock value. In practice, we would expect that there would be
/// a hardware register with accumulated mS. It would be incremented by the output
/// of a pre-scaler. The pre-scaler would divide the ticks from the clock by some
/// value that would compensate for the difference between clock time and real time.
/// The code here does the emulation of this function.
const CLOCK_NOMINAL: u32 = 30000;

#[derive(Clone, Serialize, Deserialize)]
pub struct ClockState {
    adjust_rate: u32,

    timer_reset: bool,
    timer_stopped: bool,

    // These values are used to try to synthesize a long lived version of clock().
    last_system_time: u128,
    last_reported_time: u128,

    // This is the value returned the last time that the system clock was read. This
    // is only relevant for a simulator or virtual TPM.
    last_real_time: u128,

    // This is the rate adjusted value that is the equivalent of what would be read from
    // a hardware register that produced rate adjusted time.
    tpm_time: u128,
}

impl ClockState {
    pub fn new() -> ClockState {
        ClockState {
            adjust_rate: CLOCK_NOMINAL,

            timer_reset: true,
            timer_stopped: true,

            last_system_time: 0,
            last_reported_time: 0,
            last_real_time: 0,
            tpm_time: 0,
        }
    }
}

impl MsTpm185PlatformImpl {
    /// Reset the timer.
    pub fn timer_reset(&mut self) {
        self.state.clock = ClockState::new();
    }

    // Ported over from ms-tps-20-re/TPMCmd/Platform/src/Clock.c
    fn timer_read(&mut self) -> u64 {
        let ClockState {
            adjust_rate,
            last_system_time,
            last_reported_time,
            last_real_time,
            tpm_time,
            ..
        } = &mut self.state.clock;

        let mut now = self.callbacks.monotonic_timer().as_millis();

        // if this hasn't been initialized, initialize it
        if *last_system_time == 0 {
            *last_system_time = now;
            *last_reported_time = 0;
            *last_real_time = 0;
        }

        // The system time can bounce around and that's OK as long as we don't allow
        // time to go backwards. When the time does appear to go backwards, set
        // last_system_time to be the new value and then update the reported time.
        if now < *last_reported_time {
            *last_system_time = now;
        }
        *last_reported_time = (*last_reported_time + now).wrapping_sub(*last_system_time);
        *last_system_time = now;
        now = *last_reported_time;

        // The code above produces a now that is similar to the value returned
        // by Clock(). The difference is that now does not max out, and it is
        // at a ms. rate rather than at a CLOCKS_PER_SEC rate. The code below
        // uses that value and does the rate adjustment on the time value.
        // If there is no difference in time, then skip all the computations
        if *last_real_time >= now {
            return (*tpm_time)
                .try_into()
                .expect("timestamp doesn't fit in 64 bits");
        }
        // Compute the amount of time since the last update of the system clock
        let time_diff = now - *last_real_time;

        // Do the time rate adjustment and conversion from CLOCKS_PER_SEC to mSec
        let adjusted_time_diff = (time_diff * CLOCK_NOMINAL as u128) / (*adjust_rate as u128);

        // update the TPM time with the adjusted timeDiff
        *tpm_time += adjusted_time_diff;

        // Might have some rounding error that would loose CLOCKS. See what is not
        // being used. As mentioned above, this could result in putting back more than
        // is taken out. Here, we are trying to recreate timeDiff.
        let readjusted_time_diff =
            (adjusted_time_diff * (*adjust_rate as u128)) / CLOCK_NOMINAL as u128;

        // adjusted is now converted back to being the amount we should advance the
        // previous sampled time. It should always be less than or equal to timeDiff.
        // That is, we could not have use more time than we started with.
        *last_real_time += readjusted_time_diff;

        (*tpm_time)
            .try_into()
            .expect("timestamp doesn't fit in 64 bits")
    }

    fn timer_was_reset(&mut self) -> bool {
        let ret = self.state.clock.timer_reset;
        self.state.clock.timer_reset = false;
        ret
    }

    fn timer_was_stopped(&mut self) -> bool {
        let ret = self.state.clock.timer_stopped;
        self.state.clock.timer_stopped = false;
        ret
    }

    fn clock_rate_adjust(&mut self, adjustment: i32) {
        const PLAT_TPM_CLOCK_ADJUST_COARSE_SLOWER: i32 = -3;
        const PLAT_TPM_CLOCK_ADJUST_MEDIUM_SLOWER: i32 = -2;
        const PLAT_TPM_CLOCK_ADJUST_FINE_SLOWER: i32 = -1;
        const PLAT_TPM_CLOCK_ADJUST_FINE_FASTER: i32 = 1;
        const PLAT_TPM_CLOCK_ADJUST_MEDIUM_FASTER: i32 = 2;
        const PLAT_TPM_CLOCK_ADJUST_COARSE_FASTER: i32 = 3;

        const CLOCK_ADJUST_COARSE: i32 = 300;
        const CLOCK_ADJUST_MEDIUM: i32 = 30;
        const CLOCK_ADJUST_FINE: i32 = 1;

        let tick_delta = match adjustment {
            // slower increases the divisor
            PLAT_TPM_CLOCK_ADJUST_COARSE_SLOWER => CLOCK_ADJUST_COARSE,
            PLAT_TPM_CLOCK_ADJUST_MEDIUM_SLOWER => CLOCK_ADJUST_MEDIUM,
            PLAT_TPM_CLOCK_ADJUST_FINE_SLOWER => CLOCK_ADJUST_FINE,
            // faster decreases the divisor
            PLAT_TPM_CLOCK_ADJUST_FINE_FASTER => -CLOCK_ADJUST_FINE,
            PLAT_TPM_CLOCK_ADJUST_MEDIUM_FASTER => -CLOCK_ADJUST_MEDIUM,
            PLAT_TPM_CLOCK_ADJUST_COARSE_FASTER => -CLOCK_ADJUST_COARSE,
            _ => 0,
        };

        // The clock tolerance is +/-15% (4500 counts)
        // Allow some guard band (16.7%)
        const CLOCK_ADJUST_LIMIT: i32 = 5000;
        const CLOCK_ADJUST_LIMIT_LOW: u32 = CLOCK_NOMINAL.strict_sub_signed(CLOCK_ADJUST_LIMIT);
        const CLOCK_ADJUST_LIMIT_HIGH: u32 = CLOCK_NOMINAL.strict_add_signed(CLOCK_ADJUST_LIMIT);

        self.state.clock.adjust_rate = self
            .state
            .clock
            .adjust_rate
            .strict_add_signed(tick_delta)
            .clamp(CLOCK_ADJUST_LIMIT_LOW, CLOCK_ADJUST_LIMIT_HIGH);
    }
}

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__TimerRead() -> u64 {
        platform!().timer_read()
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__TimerWasReset() -> i32 {
        platform!().timer_was_reset() as i32
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__TimerWasStopped() -> i32 {
        platform!().timer_was_stopped() as i32
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ClockRateAdjust(adjustment: i32) {
        platform!().clock_rate_adjust(adjustment)
    }
}
