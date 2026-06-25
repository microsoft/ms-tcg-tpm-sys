// Copyright (C) Microsoft Corporation. All rights reserved.

// OpenSSL 3.6.x build-compatibility shim.
//
// `TPM/.../cryptolibs/Ossl/include/Ossl/BnToOsslMath.h` raises `#error Untested
// OpenSSL version` for `OPENSSL_VERSION_NUMBER >= 0x30600000L` (OpenSSL 3.6.0).
// It does so because it shadow-declares OpenSSL's internal `bignum_st` struct,
// and the version guard is a tripwire against that private layout changing. The
// layout is in fact unchanged across the whole 3.x series through 3.6.x, so
// rather than patch the submodule-owned header we redefine the version macro to
// make the code think we're using 3.5.
//
// Only the preprocessor gate is affected. The human-readable version reported
// by `OsslGetVersion()` is taken from `OPENSSL_VERSION_STR`, which is untouched,
// so the build still links against - and reports - the real OpenSSL 3.6.x.
#ifndef MS_TCG_TPM_OSSL_VERSION_COMPAT_H
#define MS_TCG_TPM_OSSL_VERSION_COMPAT_H

// Pull in the real version macros up front so that the override below sticks
// for the rest of the translation unit. The __has_include guard leaves
// translation units that are built without OpenSSL completely untouched.
#if defined(__has_include)
#  if __has_include(<openssl/opensslv.h>)
#    include <openssl/opensslv.h>
#  endif
#endif

#if defined(OPENSSL_VERSION_NUMBER)            \
    && (OPENSSL_VERSION_NUMBER >= 0x30600000L) \
    && (OPENSSL_VERSION_NUMBER < 0x30700000L)
#  undef OPENSSL_VERSION_NUMBER
#  define OPENSSL_VERSION_NUMBER 0x30500000L
#endif

#endif  // MS_TCG_TPM_OSSL_VERSION_COMPAT_H
