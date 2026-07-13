//
// Vendor command dispatch tables
//
// This file contains the dispatch table definitions for vendor commands.
// See CommandDispatch.inl for more details about dispatch tables.
//
// The difference between vendor commands and TPM commands is in the handling.
// Vendor commands collate all dispatch tables into a global table called
// `vendorCommandDispatch` (defined at the bottom of this file), whereas TPM
// commands reference individual dispatch tables using X-macros defined in
// "DispatchID.h". However, once the dispatch table is retrieved, command
// parsing is identical.
//
// For implementors of new vendor commands, it is expected to define all of
// the following in addition to the dispatch table here:
//
// - TPM_CC_<command>: the command code for the vendor command
//   ("VendorCommandList.h")
// - <command>_In: the input struct to the command handler
//   ("prototypes/<command>_fp.h")
// - <command>_Out: the output struct populated by the command handler
//   ("prototypes/<command>_fp.h")
// - TPM2_<command>: the command handler for the vendor command
//    - declaration: "prototypes/<command>_fp.h"
//    - implementation: "TpmConfiguration/TpmVendorCommandHandlers/<command>.c"
// - Attributes for the command in "CommandAttributeData_s_ccAttr.inl" and
//   "CommandAttributeData_s_commandAttributes.inl".
//
// The command should be hooked up in the following locations:
//
// - "TPMCmd/tpm/include/private/Commands.h" conditionally includes the
//   function prototype header (<command>_fp.h).
// - Install the headers in "TpmConfiguration/CMakeLists.txt".
// - Add to the target_sources in
//   "TpmConfiguration/TpmVendorCommandHandlers/CMakeLists.txt".

#include "CommandDispatcher.h"

const VendorDispatchId vendorCommandDispatch[] = {
};
