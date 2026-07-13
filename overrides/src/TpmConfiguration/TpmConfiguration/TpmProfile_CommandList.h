
// this file defines the desired command list that should be built into the
// Tpm Core Lib.

#ifndef _TPM_PROFILE_COMMAND_LIST_H_
#define _TPM_PROFILE_COMMAND_LIST_H_

#if (YES != 1 || NO != 0)
#  error YES and NO must be correctly set before including TpmProfile_CommandList.h
#endif
#if defined(CC_YES) || defined(CC_NO)
#  error CC_YES and CC_NO should be defined by the command line file, not before
#endif

// Change these definitions to turn all commands ON or OFF. That is, to turn all
// commands on, set CC_NO to YES. This is intended as a debug feature.
#define CC_YES YES
#define CC_NO  NO

// Note: Some macros in the code depend on CC_SomeCommand being either CC_YES or
// CC_NO. Setting the macro to some expression (e.g., "(YES && ALG_ECC)") will
// break these macros.

// do not format automatically - the comments confuse clang-format.
// clang-format off

// Defines for Implemented Commands

// Commands that are defined in the spec, but not implemented for various
// reasons:

// The TPM reference implementation does not implement firmware upgrade.
#define CC_FieldUpgradeData           CC_NO
#define CC_FieldUpgradeStart          CC_NO
#define CC_FirmwareRead               CC_NO

// Normal commands:

#define CC_ActivateCredential         CC_YES
#define CC_Certify                    CC_YES
#define CC_CertifyCreation            CC_YES
#define CC_ChangeEPS                  CC_YES
#define CC_ChangePPS                  CC_YES
#define CC_Clear                      CC_YES
#define CC_ClearControl               CC_YES
#define CC_ClockRateAdjust            CC_YES
#define CC_ClockSet                   CC_YES
#define CC_ContextLoad                CC_YES
#define CC_ContextSave                CC_YES
#define CC_Create                     CC_YES
#define CC_CreateLoaded               CC_YES
#define CC_CreatePrimary              CC_YES
#define CC_DictionaryAttackLockReset  CC_YES
#define CC_DictionaryAttackParameters CC_YES
#define CC_Duplicate                  CC_YES
#define CC_EncryptDecrypt             CC_YES
#define CC_EncryptDecrypt2            CC_YES
#define CC_EventSequenceComplete      CC_YES
#define CC_EvictControl               CC_YES
#define CC_FlushContext               CC_YES
#define CC_GetCapability              CC_YES
#define CC_GetCommandAuditDigest      CC_YES
#define CC_GetRandom                  CC_YES
#define CC_GetSessionAuditDigest      CC_YES
#define CC_GetTestResult              CC_YES
#define CC_GetTime                    CC_YES
#define CC_Hash                       CC_YES
#define CC_HashSequenceStart          CC_YES
#define CC_HierarchyChangeAuth        CC_YES
#define CC_HierarchyControl           CC_YES
#define CC_Import                     CC_YES
#define CC_IncrementalSelfTest        CC_YES
#define CC_Load                       CC_YES
#define CC_LoadExternal               CC_YES
#define CC_MakeCredential             CC_YES
#define CC_NV_Certify                 CC_YES
#define CC_NV_ChangeAuth              CC_YES
#define CC_NV_DefineSpace             CC_YES
#define CC_NV_Extend                  CC_YES
#define CC_NV_GlobalWriteLock         CC_YES
#define CC_NV_Increment               CC_YES
#define CC_NV_Read                    CC_YES
#define CC_NV_ReadLock                CC_YES
#define CC_NV_ReadPublic              CC_YES
#define CC_NV_SetBits                 CC_YES
#define CC_NV_UndefineSpace           CC_YES
#define CC_NV_UndefineSpaceSpecial    CC_YES
#define CC_NV_Write                   CC_YES
#define CC_NV_WriteLock               CC_YES
#define CC_ObjectChangeAuth           CC_YES
#define CC_PCR_Allocate               CC_YES
#define CC_PCR_Event                  CC_YES
#define CC_PCR_Extend                 CC_YES
#define CC_PCR_Read                   CC_YES
#define CC_PCR_Reset                  CC_YES
#define CC_PCR_SetAuthPolicy          CC_YES
#define CC_PCR_SetAuthValue           CC_YES
#define CC_PP_Commands                CC_YES
#define CC_PolicyAuthValue            CC_YES
#define CC_PolicyAuthorize            CC_YES
#define CC_PolicyAuthorizeNV          CC_YES
#define CC_PolicyCapability           CC_YES
#define CC_PolicyCommandCode          CC_YES
#define CC_PolicyCounterTimer         CC_YES
#define CC_PolicyCpHash               CC_YES
#define CC_PolicyDuplicationSelect    CC_YES
#define CC_PolicyGetDigest            CC_YES
#define CC_PolicyLocality             CC_YES
#define CC_PolicyNV                   CC_YES
#define CC_PolicyNameHash             CC_YES
#define CC_PolicyNvWritten            CC_YES
#define CC_PolicyOR                   CC_YES
#define CC_PolicyPCR                  CC_YES
#define CC_PolicyPassword             CC_YES
#define CC_PolicyParameters           CC_YES
#define CC_PolicyPhysicalPresence     CC_YES
#define CC_PolicyRestart              CC_YES
#define CC_PolicySecret               CC_YES
#define CC_PolicySigned               CC_YES
#define CC_PolicyTemplate             CC_YES
#define CC_PolicyTicket               CC_YES
#define CC_Quote                      CC_YES
#define CC_ReadClock                  CC_YES
#define CC_ReadPublic                 CC_YES
#define CC_Rewrap                     CC_YES
#define CC_SelfTest                   CC_YES
#define CC_SequenceComplete           CC_YES
#define CC_SequenceUpdate             CC_YES
#define CC_SetAlgorithmSet            CC_YES
#define CC_SetCommandCodeAuditStatus  CC_YES
#define CC_SetPrimaryPolicy           CC_YES
#define CC_Shutdown                   CC_YES
#define CC_Sign                       CC_YES
#define CC_StartAuthSession           CC_YES
#define CC_Startup                    CC_YES
#define CC_StirRandom                 CC_YES
#define CC_TestParms                  CC_YES
#define CC_Unseal                     CC_YES
#define CC_VerifySignature            CC_YES
#define CC_NV_DefineSpace2            CC_YES
#define CC_NV_ReadPublic2             CC_YES
// Disabled because there are no settable capabilities for this simulator.
#define CC_SetCapability              CC_NO
#define CC_ReadOnlyControl            CC_YES
#define CC_PolicyTransportSPDM        CC_YES
#define CC_VerifySequenceStart        CC_YES
#define CC_SignSequenceStart          CC_YES
#define CC_VerifySequenceComplete     CC_YES
#define CC_SignSequenceComplete       CC_YES
#define CC_VerifyDigestSignature      CC_YES
#define CC_SignDigest                 CC_YES
#define CC_Encapsulate                CC_YES
#define CC_Decapsulate                CC_YES


// Commands that depend on ACT support:

#if ACT_SUPPORT
#define CC_ACT_SetTimeout             CC_YES
#else
#define CC_ACT_SetTimeout             CC_NO
#endif

// Commands that depend on ECC:

#if ALG_ECC
#define CC_Commit                     CC_YES
#define CC_ECC_Decrypt                CC_YES
#define CC_ECC_Encrypt                CC_YES
#define CC_ECC_Parameters             CC_YES
#define CC_ECDH_KeyGen                CC_YES
#define CC_ECDH_ZGen                  CC_YES
#define CC_EC_Ephemeral               CC_YES
#define CC_ZGen_2Phase                CC_YES
#else
#define CC_Commit                     CC_NO
#define CC_ECC_Decrypt                CC_NO
#define CC_ECC_Encrypt                CC_NO
#define CC_ECC_Parameters             CC_NO
#define CC_ECDH_KeyGen                CC_NO
#define CC_ECDH_ZGen                  CC_NO
#define CC_EC_Ephemeral               CC_NO
#define CC_ZGen_2Phase                CC_NO
#endif

// Commands that depend on RSA:

#if ALG_RSA
#define CC_RSA_Decrypt                CC_YES
#define CC_RSA_Encrypt                CC_YES
#else
#define CC_RSA_Decrypt                CC_NO
#define CC_RSA_Encrypt                CC_NO
#endif

// Only one of (CMAC, MAC) are allowed because they share a command code:
#if ALG_CMAC
#define CC_MAC                        CC_YES
#define CC_MAC_Start                  CC_YES
#define CC_HMAC                       CC_NO
#define CC_HMAC_Start                 CC_NO
#else
#define CC_MAC                        CC_NO
#define CC_MAC_Start                  CC_NO
#define CC_HMAC                       CC_YES
#define CC_HMAC_Start                 CC_YES
#endif

// clang-format on

#include <TpmConfiguration/VendorCommands/VendorCommandList.h>

#endif  // _TPM_PROFILE_COMMAND_LIST_H_
