// Copyright (C) Microsoft Corporation. All rights reserved.

// HACK: Copy this one function here so that we can inject it into the SymCrypt
// build of the TPM without also pulling in the incompatible SymCrypt callbacks
// that the rest of `SymCryptSupport.c` defines.

#include <SymCrypt/TpmToSymCrypt.h>

//*** Sc_HashFromTpm()
// Map a TPM hash algorithm id to the matching SymCrypt hash object.
//  Return Type: PCSYMCRYPT_HASH
//      non-NULL        the SymCrypt hash for a supported algorithm
//      NULL            the algorithm is not supported
PCSYMCRYPT_HASH Sc_HashFromTpm(TPM_ALG_ID hashAlg)
{
    switch(hashAlg)
    {
#if ALG_SHA1
        case TPM_ALG_SHA1:
            return SymCryptSha1Algorithm;
#endif
#if ALG_SHA256
        case TPM_ALG_SHA256:
            return SymCryptSha256Algorithm;
#endif
#if ALG_SHA384
        case TPM_ALG_SHA384:
            return SymCryptSha384Algorithm;
#endif
#if ALG_SHA512
        case TPM_ALG_SHA512:
            return SymCryptSha512Algorithm;
#endif
        // For an unsupported algorithm, returns NULL so the caller maps it to
        // TPM_RC_SCHEME.
        default:
            return NULL;
    }
}
