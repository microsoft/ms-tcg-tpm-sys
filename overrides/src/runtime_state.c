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
typedef HASH_OBJECT_BUFFER SEQUENCE_OBJECT_BUFFER;
#define CryptoHash_GetHashDef CryptGetHashDef
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

// The header structure for vTPM run-time state blob.
typedef struct tag_TPM_RUNTIME_STATE_HEADER
{
    // Contains a sequence of "VTPMRTST".
    uint64_t HeaderMagic64;

    // Must match the local vTPM platform revision, so that a blob is only ever
    // applied to a build saving the same set of variables.
    uint32_t Revision;

    // Number of variables for which the data is present in the runtime state blob.
    uint32_t VariableCount;

} TPM_RUNTIME_STATE_HEADER, *PTPM_RUNTIME_STATE_HEADER;

static const uint64_t s_RuntimeStateHeaderMagic = 0x545354524D505456;  // "VTPMRTST"

// Increment on every change to the number or type of globals saved below.
static const uint32_t s_RuntimeStateRevision = 0x10;

// The variable table below is only complete for the build switches this profile
// selects; flipping any of these adds a global that would silently go unsaved.
TPM_STATIC_ASSERT(ACCUMULATE_SELF_HEAL_TIMER == YES);  // else s_selfHealTimer + s_lockoutTimer
TPM_STATIC_ASSERT(VENDOR_PERMANENT_AUTH_ENABLED == NO);  // else g_platformUniqueAuth
TPM_STATIC_ASSERT(CLOCK_STOPS == YES);  // else g_timeEpoch aliases gp.timeEpoch
TPM_STATIC_ASSERT(USE_DA_USED == YES);  // else g_daUsed below is not declared
TPM_STATIC_ASSERT(ACT_SUPPORT == NO);  // else s_ActUpdated
TPM_STATIC_ASSERT(SIMULATION == NO);  // else simulation-only state
TPM_STATIC_ASSERT(DEBUG == NO);  // else debug-only state
TPM_STATIC_ASSERT(RSA_INSTRUMENT == NO);  // else RSA instrumentation state
TPM_STATIC_ASSERT(USE_RSA_KEY_CACHE == NO);  // else RSA key cache state

// Contains information about a single run-time variable.
typedef struct tag_TPM_RUNTIME_STATE_ENTRY
{
    // Pointer to a variable.
    void *pbRuntimeVariable;

    // Variable size.
    const uint32_t cbVariableSize;

} TPM_RUNTIME_STATE_ENTRY;

// Enumerates all run-time variables inside the TPM engine and platform (as defined in Global.h).
static const TPM_RUNTIME_STATE_ENTRY s_TpmRuntimeVariables[] =
    {
        // {(char *)&g_implementedAlgorithms, sizeof(g_implementedAlgorithms)},
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
        // {(char *)&g_updateNV, sizeof(g_updateNV)},
        {(char *)&g_powerWasLost, sizeof(g_powerWasLost)},
        // {(char *)&g_clearOrderly, sizeof(g_clearOrderly)},
        {(char *)&g_prevOrderlyState, sizeof(g_prevOrderlyState)},
        {(char *)&g_nvOk, sizeof(g_nvOk)},
        // {(char *)&g_NvStatus, sizeof(g_NvStatus)},
        {(char *)&gp, sizeof(gp)},
        {(char *)&go, sizeof(go)},
        {(char *)&gc, sizeof(gc)},
        {(char *)&gr, sizeof(gr)},
        {(char *)&g_cryptoSelfTestState, sizeof(g_cryptoSelfTestState)},
        {(char *)&g_manufactured, sizeof(g_manufactured)},
        {(char *)&g_initialized, sizeof(g_initialized)},
        {(char *)&g_initCompleted, sizeof(g_initCompleted)},
        // {(char *)s_sessionHandles, sizeof(s_sessionHandles)},
        // {(char *)s_attributes, sizeof(s_attributes)},
        // {(char *)s_associatedHandles, sizeof(s_associatedHandles)},
        // {(char *)s_nonceCaller, sizeof(s_nonceCaller)},
        // {(char *)s_inputAuthValues, sizeof(s_inputAuthValues)},
        // {(char *)s_usedSessions, sizeof(s_usedSessions)},
        // {(char *)&s_encryptSessionIndex, sizeof(s_encryptSessionIndex)},
        // {(char *)&s_decryptSessionIndex, sizeof(s_decryptSessionIndex)},
        // {(char *)&s_auditSessionIndex, sizeof(s_auditSessionIndex)},
        // {(char *)&s_cpHashForCommandAudit, sizeof(s_cpHashForCommandAudit)},
        {(char *)&s_DAPendingOnNV, sizeof(s_DAPendingOnNV)},
        // {(char *)&s_evictNvEnd, sizeof(s_evictNvEnd)},
        {(char *)&s_indexOrderlyRam, sizeof(s_indexOrderlyRam)},
        {(char *)&s_maxCounter, sizeof(s_maxCounter)},
        // {(char *)&s_cachedNvIndex, sizeof(s_cachedNvIndex)},
        // {(char *)&s_cachedNvRef, sizeof(s_cachedNvRef)},
        // {(char *)&s_cachedNvRamRef, sizeof(s_cachedNvRamRef)},
        {(char *)s_objects, sizeof(s_objects)},
        {(char *)s_pcrs, sizeof(s_pcrs)},
        {(char *)s_sessions, sizeof(s_sessions)},
        {(char *)&s_oldestSavedSession, sizeof(s_oldestSavedSession)},
        {(char *)&s_freeSessionSlots, sizeof(s_freeSessionSlots)},
        // {(char *)s_actionIoBuffer, sizeof(s_actionIoBuffer)},
        // {(char *)&s_actionIoAllocation, sizeof(s_actionIoAllocation)},
        // {(char *)&s_ActUpdated, sizeof(s_ActUpdated)},
        // {(char *)failure_response_buffer, sizeof(failure_response_buffer)},
        // {(char *)&primeLimit, sizeof(primeLimit)},

        // Deliberately excluded, all re-initialized before use within a single
        // ExecuteCommand() and therefore never live across a save/restore:
        //  - s_actionIoBuffer / s_actionIoAllocation (IoBuffers.c)
        //  - failure_response_buffer (TpmFail.c)
        //  - primeLimit (CryptPrimeSieve.c)
        //  - the static scratch buffers in AlgorithmTests.c
        //  - s_sessionHandles / s_attributes / s_associatedHandles /
        //    s_nonceCaller / s_inputAuthValues and s_encryptSessionIndex /
        //    s_decryptSessionIndex / s_auditSessionIndex
        //    (RetrieveSessionData())
        //  - g_updateNV / g_clearOrderly (ExecuteCommand(), including its
        //    failure-mode return)
        //  - g_NvStatus (NvCheckState(), before any reader)
        //
        // Also deliberately excluded:
        //  - g_implementedAlgorithms carries no information:
        //    AlgorithmGetImplementedVector() derives it entirely from the
        //    compile-time s_algorithms[] table during _TPM_Init()
        //  - s_evictNvEnd is initialized from the compile-time NV_MEMORY_SIZE
        //    during _TPM_Init(), before runtime state can be applied
        //  - s_usedSessions is never referenced by the TPM implementation
        //  - s_cpHashForCommandAudit is never referenced by the TPM implementation
        //  - s_ActUpdated is unused because this profile disables ACT support
};

// Swaps each sequence object's running state for its exported form in a saved
// copy of `s_objects`.
//
// SequenceDataExport() is the library's own TPM2_ContextSave path: it replaces
// an ML-DSA crypto handle with its serialized form and runs each hash context
// through the backend's copyOut, either of which would otherwise leave an
// address from this process in the blob.
static void
ExportSequenceObjectStates(char *savedObjects)
{
    for (uint32_t i = 0; i < ARRAY_SIZE(s_objects); i++)
    {
        OBJECT *object = &s_objects[i];

        if (object->attributes.occupied != TRUE || !ObjectIsSequence(object))
        {
            continue;
        }

        // Staged through an aligned copy because the blob is packed, and
        // because export needs a destination distinct from the live object.
        OBJECT staged = *object;

        SequenceDataExport((SEQUENCE_OBJECT *)object, (SEQUENCE_OBJECT_BUFFER *)&staged);
        memcpy(savedObjects + (size_t)i * sizeof(OBJECT), &staged, sizeof(staged));
    }
}

// Rebuilds the running state of every sequence object, in place.
//
// SequenceDataImport() is the library's own TPM2_ContextLoad path: it rebinds
// HASH_STATE.def, runs the backend's hash-context copyIn, and turns an exported
// ML-DSA state back into a live crypto handle.
//
// Runs after the blob has been copied over s_objects, so the exported form is
// already there; it is staged out because the ML-DSA branch writes a fresh
// handle into the same union it reads the exported form from.
static bool
ImportSequenceObjectStates(void)
{
    bool wasInFailureMode = _plat__InFailureMode();

    for (uint32_t i = 0; i < ARRAY_SIZE(s_objects); i++)
    {
        OBJECT *object = &s_objects[i];

        if (object->attributes.occupied != TRUE || !ObjectIsSequence(object))
        {
            continue;
        }

        OBJECT staged = *object;

        SequenceDataImport((SEQUENCE_OBJECT *)object, (SEQUENCE_OBJECT_BUFFER *)&staged);

        if (!wasInFailureMode && _plat__InFailureMode())
        {
            return false;
        }

        SEQUENCE_OBJECT *sequence = (SEQUENCE_OBJECT *)object;

#ifdef TPM_ALG_MLDSA
        // An ML-DSA sequence holds a crypto handle in this union rather than
        // hash contexts, and those bytes could read as HASH_STATE_SMAC. Both
        // halves of the test matter and mirror SequenceDataImport()'s own
        // dispatch: AllocateSequenceSlot() leaves signScheme uninitialized, so
        // on its own the scheme can be a stale TPM_ALG_MLDSA from a previous
        // tenant of the slot.
        if ((object->attributes.signSeq == SET || object->attributes.verifySeq == SET)
            && sequence->signScheme.scheme == TPM_ALG_MLDSA)
        {
            continue;
        }
#endif

        // The import restores an SMAC context with a plain memcpy, leaving the
        // saving process's method pointers in place.
        int count = (sequence->attributes.eventSeq) ? HASH_COUNT : 1;

        for (int j = 0; j < count; j++)
        {
            HASH_STATE *hash = &sequence->state.hashState[j];

            if (hash->type == HASH_STATE_SMAC)
            {
                hash->def = NULL;
                hash->state.smac.smacMethods.data = CryptCmacData;
                hash->state.smac.smacMethods.end = CryptCmacEnd;
            }
        }
    }

    return true;
}

static uint32_t
GetRuntimeStateSize(void)
{
    uint32_t totalSize = 0;

    for (uint32_t i = 0; i < ARRAY_SIZE(s_TpmRuntimeVariables); i++)
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

    // The caller's buffer is a byte array with no alignment guarantee, so the
    // header is assembled locally and copied in rather than written through a
    // struct pointer into it.
    TPM_RUNTIME_STATE_HEADER header;

    header.HeaderMagic64 = s_RuntimeStateHeaderMagic;
    header.Revision = s_RuntimeStateRevision;
    header.VariableCount = ARRAY_SIZE(s_TpmRuntimeVariables);

    memcpy(pBuffer, &header, sizeof(header));

    char *pRuntimeState = (char *)pBuffer + sizeof(header);

    for (uint32_t i = 0; i < ARRAY_SIZE(s_TpmRuntimeVariables); i++)
    {
        memcpy(pRuntimeState, s_TpmRuntimeVariables[i].pbRuntimeVariable, s_TpmRuntimeVariables[i].cbVariableSize);

        // Done here rather than after the loop so there is no case where the
        // object image was not found: the blob would otherwise be emitted
        // carrying a pointer into this process.
        if (s_TpmRuntimeVariables[i].pbRuntimeVariable == (char *)s_objects)
        {
            ExportSequenceObjectStates(pRuntimeState);
        }

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
// - 4 for sequence state import error
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

    // Copied out rather than read through a struct pointer: the blob is a byte
    // buffer with no alignment guarantee, and it is const.
    TPM_RUNTIME_STATE_HEADER header;

    memcpy(&header, pRuntimeStateBuffer, sizeof(header));

    if (header.HeaderMagic64 != s_RuntimeStateHeaderMagic
        || header.Revision != s_RuntimeStateRevision
        || header.VariableCount != ARRAY_SIZE(s_TpmRuntimeVariables))
    {
        return 3;
    }

    const char *pRuntimeState = (const char *)pRuntimeStateBuffer + sizeof(header);

    // s_objects is about to be overwritten, taking with it the only reference
    // to any crypto library state a sequence object still owns.
    for (uint32_t i = 0; i < ARRAY_SIZE(s_objects); i++)
    {
        ObjectFlush(&s_objects[i]);
    }

    for (uint32_t i = 0; i < ARRAY_SIZE(s_TpmRuntimeVariables); i++)
    {
        memcpy(s_TpmRuntimeVariables[i].pbRuntimeVariable, pRuntimeState, s_TpmRuntimeVariables[i].cbVariableSize);

        pRuntimeState += s_TpmRuntimeVariables[i].cbVariableSize;
    }

    // The NV Index cache holds a raw pointer into s_indexOrderlyRam and is not
    // part of the blob, so drop whatever this process happened to have cached.
    NvIndexCacheInit();

    if (!ImportSequenceObjectStates())
    {
        return 4;
    }

    return 0;
}
