// This file defines any Vendor command IDs, and must also define the
// VENDOR_COMMAND_ARRAY_COUNT which is consumed by the CoreLibrary.
// This file is included inside TpmProfile_CommandList.h and therefore
// has access to CC_YES and CC_NO for turning commands on and off.

#ifndef _TPM_PROFILE_COMMAND_LIST_H_
#  error This file should be included only within TpmProfile_CommandList.h
#endif

#define CC_Vendor_TCG_Test CC_NO

#define VENDOR_COMMAND_ARRAY_COUNT (0)