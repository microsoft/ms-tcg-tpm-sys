// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Hooks to save/restore all live global state of the TPM library
//
// This is not functionality built into ms-tcg-tpm-sys, as it's a pretty niche
// requirement (only really relevant for things like vTPMs, which must support
// live save/restore).

#include <stdbool.h>
#include <stdint.h>

// We only want to *reference* the globals defined by Global.c; we must NOT
// define GLOBAL_C here, or Global.h's EXTERN macro will expand to nothing and
// we'll get duplicate-symbol errors at link time.
//
// However, several of the static globals we save are wrapped in
// `#if defined(<source-file>_C) || defined(GLOBAL_C)` blocks. To get the
// `extern` declarations into scope without instantiating storage, we define
// the relevant per-source-file macros here.
#define SESSION_PROCESS_C
#define NV_C
#define OBJECT_C
#define PCR_C
#define SESSION_C
#include "Tpm.h"
#include "Global.h"

#if __has_include(<private/CryptCmac_fp.h>)
#include <private/CryptCmac_fp.h>
#else
// 184_COMPAT
#include <private/prototypes/CryptCmac_fp.h>
typedef HASH_OBJECT SEQUENCE_OBJECT;
#define CryptoHash_GetHashDef CryptGetHashDef
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

//
// The header structure for vTPM run-time state blob.
//
typedef struct tag_TPM_RUNTIME_STATE_HEADER
{
    //
    // Contains a sequence of "VTPMRTST".
    //
    uint64_t HeaderMagic64;

    //
    // A number which has to match the local vTPM platform revision number to ensure the same set of static variables is getting saved and restored.
    //
    uint32_t Revision;

    //
    // Number of variables for which the data is present in the runtime state blob.
    //
    uint32_t VariableCount;

} TPM_RUNTIME_STATE_HEADER, *PTPM_RUNTIME_STATE_HEADER;

//
// Runtime state header magic value of "VTPMRTST".
//
static const uint64_t s_RuntimeStateHeaderMagic = 0x545354524D505456;

//
// Increment this revision on every change to the number or type of global static variables used by the TPM engine.
//
static const uint32_t s_RuntimeStateRevision = 0x10;

// The variable table below is only complete for the build switches this profile
// selects; flipping any of these adds a global that would silently go unsaved.
TPM_STATIC_ASSERT(ACCUMULATE_SELF_HEAL_TIMER == YES);  // else s_selfHealTimer + s_lockoutTimer
TPM_STATIC_ASSERT(VENDOR_PERMANENT_AUTH_ENABLED == NO);  // else g_platformUniqueAuth
TPM_STATIC_ASSERT(CLOCK_STOPS == YES);  // else g_timeEpoch aliases gp.timeEpoch

//
// Contains information about a single run-time variable.
//
typedef struct tag_TPM_RUNTIME_STATE_ENTRY
{
    //
    // Pointer to a variable.
    //
    void *pbRuntimeVariable;

    //
    // Variable size.
    //
    const uint32_t cbVariableSize;

} TPM_RUNTIME_STATE_ENTRY;

//
// Enumerates all run-time variables inside the TPM engine and platform (as defined in Global.h).
//
static const TPM_RUNTIME_STATE_ENTRY s_TpmRuntimeVariables[] =
    {
        {(char *)&g_implementedAlgorithms, sizeof(g_implementedAlgorithms)},
        {(char *)&g_toTest, sizeof(g_toTest)},
        {(char *)&g_exclusiveAuditSession, sizeof(g_exclusiveAuditSession)},
        {(char *)&g_time, sizeof(g_time)},
        {(char *)&g_timeEpoch, sizeof(g_timeEpoch)},
        {(char *)&g_phEnable, sizeof(g_phEnable)},
        {(char *)&g_pcrReConfig, sizeof(g_pcrReConfig)},
        {(char *)&g_DRTMHandle, sizeof(g_DRTMHandle)},
        {(char *)&g_DrtmPreStartup, sizeof(g_DrtmPreStartup)},
        {(char *)&g_StartupLocality3, sizeof(g_StartupLocality3)},
        {(char *)&g_daUsed, sizeof(g_daUsed)},
        {(char *)&g_updateNV, sizeof(g_updateNV)},
        {(char *)&g_powerWasLost, sizeof(g_powerWasLost)},
        {(char *)&g_clearOrderly, sizeof(g_clearOrderly)},
        {(char *)&g_prevOrderlyState, sizeof(g_prevOrderlyState)},
        {(char *)&g_nvOk, sizeof(g_nvOk)},
        {(char *)&g_NvStatus, sizeof(g_NvStatus)},
        {(char *)&gp, sizeof(gp)},
        {(char *)&go, sizeof(go)},
        {(char *)&gc, sizeof(gc)},
        {(char *)&gr, sizeof(gr)},
        {(char *)&g_cryptoSelfTestState, sizeof(g_cryptoSelfTestState)},
        {(char *)&g_manufactured, sizeof(g_manufactured)},
        {(char *)&g_initialized, sizeof(g_initialized)},
        {(char *)&g_initCompleted, sizeof(g_initCompleted)},
        {(char *)s_sessionHandles, sizeof(s_sessionHandles)},
        {(char *)s_attributes, sizeof(s_attributes)},
        {(char *)s_associatedHandles, sizeof(s_associatedHandles)},
        {(char *)s_nonceCaller, sizeof(s_nonceCaller)},
        {(char *)s_inputAuthValues, sizeof(s_inputAuthValues)},
        {(char *)&s_encryptSessionIndex, sizeof(s_encryptSessionIndex)},
        {(char *)&s_decryptSessionIndex, sizeof(s_decryptSessionIndex)},
        {(char *)&s_auditSessionIndex, sizeof(s_auditSessionIndex)},
        {(char *)&s_cpHashForCommandAudit, sizeof(s_cpHashForCommandAudit)},
        {(char *)&s_DAPendingOnNV, sizeof(s_DAPendingOnNV)},
        {(char *)&s_evictNvEnd, sizeof(s_evictNvEnd)},
        {(char *)&s_indexOrderlyRam, sizeof(s_indexOrderlyRam)},
        {(char *)&s_maxCounter, sizeof(s_maxCounter)},
        {(char *)s_objects, sizeof(s_objects)},
        {(char *)s_pcrs, sizeof(s_pcrs)},
        {(char *)s_sessions, sizeof(s_sessions)},
        {(char *)&s_oldestSavedSession, sizeof(s_oldestSavedSession)},
        {(char *)&s_freeSessionSlots, sizeof(s_freeSessionSlots)},
        {(char *)&s_ActUpdated, sizeof(s_ActUpdated)},

        // Deliberately excluded, all re-initialized before use within a single
        // ExecuteCommand() and therefore never live across a save/restore:
        //  - s_actionIoBuffer / s_actionIoAllocation (IoBuffers.c)
        //  - failure_response_buffer (TpmFail.c)
        //  - primeLimit (CryptPrimeSieve.c)
        //  - the static scratch buffers in AlgorithmTests.c
};

// Sequence objects live in s_objects type-punned as SEQUENCE_OBJECT, and cache a
// HASH_DEF* (and, for CMAC, two method pointers) that are addresses in the
// saving process's image. Rebuild them the way CryptoHash_ImportState does
// instead of trusting whatever came out of the blob.
static void
RebindSequenceObjectMethods(void)
{
    for (uint32_t i = 0; i < ARRAY_SIZE(s_objects); i++)
    {
        OBJECT *object = &s_objects[i];

        if (object->attributes.occupied != TRUE || !ObjectIsSequence(object))
        {
            continue;
        }

        SEQUENCE_OBJECT *sequence = (SEQUENCE_OBJECT *)object;

        // An event sequence runs one hash per PCR bank; hash and HMAC sequences
        // only ever use the first slot.
        int count = (sequence->attributes.eventSeq) ? HASH_COUNT : 1;

        for (int j = 0; j < count; j++)
        {
            HASH_STATE *hash = &sequence->state.hashState[j];

#ifdef HASH_STATE_SMAC
            if (hash->type == HASH_STATE_SMAC)
            {
                hash->def = NULL;
                hash->state.smac.smacMethods.data = CryptCmacData;
                hash->state.smac.smacMethods.end = CryptCmacEnd;
                continue;
            }
#endif
            // Yields the null descriptor for TPM_ALG_NULL or an unknown
            // algorithm, so a corrupt blob can't leave a stale pointer behind.
            hash->def = CryptoHash_GetHashDef(hash->hashAlg);
        }
    }
}

static uint32_t
GetRuntimeStateSize(void)
{
    uint32_t totalSize = 0;
    uint32_t i;

    for (i = 0; i < ARRAY_SIZE(s_TpmRuntimeVariables); i++)
    {
        totalSize += s_TpmRuntimeVariables[i].cbVariableSize;
    }

    return totalSize + sizeof(TPM_RUNTIME_STATE_HEADER);
}

// Returns:
// - 0 on success
// - 1 for invalid arg
// - 2 for insufficient size (setting pBufferSize to required size)
int INJECTED_GetRuntimeState(
    void *pBuffer,
    uint32_t *pBufferSize)
{
    if (pBufferSize == NULL ||
        (pBuffer == NULL && *pBufferSize != 0))
    {
        return 1;
    }

    uint32_t requiredSize = GetRuntimeStateSize();

    if (*pBufferSize < requiredSize)
    {
        *pBufferSize = requiredSize;
        return 2;
    }

    PTPM_RUNTIME_STATE_HEADER pHeader = (PTPM_RUNTIME_STATE_HEADER)pBuffer;

    pHeader->HeaderMagic64 = s_RuntimeStateHeaderMagic;
    pHeader->Revision = s_RuntimeStateRevision;
    pHeader->VariableCount = ARRAY_SIZE(s_TpmRuntimeVariables);

    char *pRuntimeState = (char *)(pHeader + 1);

    for (uint32_t i = 0; i < ARRAY_SIZE(s_TpmRuntimeVariables); i++)
    {
        memcpy(pRuntimeState, s_TpmRuntimeVariables[i].pbRuntimeVariable, s_TpmRuntimeVariables[i].cbVariableSize);

        pRuntimeState += s_TpmRuntimeVariables[i].cbVariableSize;
    }

    *pBufferSize = requiredSize;

    return 0;
}

// Returns:
// - 0 on success
// - 1 for invalid arg
// - 2 for size mismatch
// - 3 for format validation error
int INJECTED_ApplyRuntimeState(
    const void *pRuntimeStateBuffer,
    uint32_t runtimeStateBufferSize)
{
    if (pRuntimeStateBuffer == NULL)
    {
        return 1;
    }

    uint32_t requiredSize = GetRuntimeStateSize();

    if (runtimeStateBufferSize != requiredSize)
    {
        return 2;
    }

    PTPM_RUNTIME_STATE_HEADER pHeader = (PTPM_RUNTIME_STATE_HEADER)pRuntimeStateBuffer;

    if (pHeader->HeaderMagic64 != s_RuntimeStateHeaderMagic ||
        pHeader->Revision != s_RuntimeStateRevision ||
        pHeader->VariableCount != ARRAY_SIZE(s_TpmRuntimeVariables))
    {
        return 3;
    }

    char *pRuntimeState = (char *)(pHeader + 1);

    for (uint32_t i = 0; i < ARRAY_SIZE(s_TpmRuntimeVariables); i++)
    {
        memcpy(s_TpmRuntimeVariables[i].pbRuntimeVariable, pRuntimeState, s_TpmRuntimeVariables[i].cbVariableSize);

        pRuntimeState += s_TpmRuntimeVariables[i].cbVariableSize;
    }

    // The NV Index cache holds a raw pointer into s_indexOrderlyRam and is not
    // part of the blob, so drop whatever this process happened to have cached.
    NvIndexCacheInit();

    RebindSequenceObjectMethods();

    return 0;
}
