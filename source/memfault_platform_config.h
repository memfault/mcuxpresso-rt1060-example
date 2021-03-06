#pragma once

//! @file
//!
//! Copyright (c) Memfault, Inc.
//! See License.txt for details
//!
//! Platform overrides for the default configuration settings in the memfault-firmware-sdk.
//! Default configuration settings can be found in "memfault/config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Enable GNU build ID
#define MEMFAULT_USE_GNU_BUILD_ID 1

// Explicitly capture log buffer in coredump
#define MEMFAULT_COREDUMP_COLLECT_LOG_REGIONS 1

// Application takes about 150kB, add 2 more kB for registers etc
#define MEMFAULT_PLATFORM_COREDUMP_STORAGE_RAM_SIZE (250 * 1024)

// For demonstration purposes in this example app, setting the heartbeat
// interval to be low
#define MEMFAULT_METRICS_HEARTBEAT_INTERVAL_SECS 60

#ifdef __cplusplus
}
#endif
