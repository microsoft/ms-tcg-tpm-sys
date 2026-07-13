##########################################################
# DO NOT MODIFY - TPM Configuration Library
##########################################################
# The contents of the source files may be modified to specify any valid
# desired configuraton.  However, the CMake library name "TpmConfiguration"
# is required by the CoreLib to reference this project.  Recommend making
# no changes in this file.
cmake_minimum_required(VERSION 3.16.3)

if(NOT PROJECT_IS_TOP_LEVEL)
    message(FATAL_ERROR "TpmConfiguration folder from TPM Core library must be only included from top-level project.")
endif()

# set the project name and version
# Must be TpmConfiguration
project(TpmConfiguration VERSION 1.0)
print_project_info()

# use standard output directories.  Expected by package_utilities
include(GNUInstallDirs)

add_library(TpmConfiguration INTERFACE)
add_library(TpmConfiguration::TpmConfiguration ALIAS TpmConfiguration)

target_include_directories(${PROJECT_NAME}
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration>"
)

# MSVC: Warn on most things, and treat them as errors.
set(MSVC_OPTIONS /WX /Wall)
# enable minimal rebuild
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /Gm-)

# for some reason the built-in limits.h complains without this on MSVC.
# minimal repro https://stackoverflow.com/questions/66408981/iostream-and-define-stdc-want-secure-lib-0-results-in-error-c2039-sprin
set(MSVC_OPTIONS "${MSVC_OPTIONS}" -D__STDC_WANT_SECURE_LIB__=1)

set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4034) # turn off C4034: sizeof returns 0
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4065) # turn off C4065: switch statement contains 'default' but no 'case' labels
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4127) # turn off C4127: conditional expression is constant
# turn off C4191: the Hash function typedefs use casts that trigger
# unsafe cast warnings.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4191)
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4514) # turn off C4514: unreferenced inline function removed
# C++ default constructor / copy assignment / move assignment
# are implicitly defined as deleted when including SelfTest.h
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4623 /wd4626 /wd5027)
# turn off C4668: 'x' is not defined as a preprocessor macro, replacing
# with '0' for '#if/#elif' this is actually unsafe for the TPM code
# because this error can happen if there is a mismatch between the core
# library and the configuration provided by the consuming code. However,
# some build servers necessitate this because they use old Windows SDK
# headers that don't build cleanly.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4668)
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4702) # turn off C4702: unreachable code warnings
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4710) # turn off C4710: function not inlined
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4820) # turn off C4820: alignment padding warnings
# TODO: This disables warnings for deprecated functions and should not be
# considered a permanent fix. Deprecated functions should be replaced.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4996)
# turn off C5039: 'OPENSSL_sk_new': pointer or reference to potentially
# throwing function passed to 'extern "C"' function under -EHc.
# Undefined behavior may occur if this function throws an exception.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd5039)
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd5045) # turn off C5045: Spectre mitigation warnings

# Warn on most things, and treat them as errors.
set(GCC_OPTIONS -Wall -Wextra -Werror -pedantic)
# Warn if unable to inline a TPM_INLINE function (GCC only, no-op on Clang).
set(GCC_OPTIONS "${GCC_OPTIONS}" -Winline)
# Warn about implicit fallthrough (not included in -Wextra for Clang)
set(GCC_OPTIONS "${GCC_OPTIONS}" -Wimplicit-fallthrough)

# The hash state/function headers and marshalling/unmarshalling perform
# function casts that trigger this error.
set(GCC_OPTIONS "${GCC_OPTIONS}" -Wno-cast-function-type)

# This is needed when compiling against OpenSSL 3.0, as the Ossl bindings use:
#  - EC_POINT_set_affine_coordinates_GFp / EC_POINTs_mul
#  - AES_set_encrypt_key / AES_encrypt
#  - Camellia_set_key / Camellia_encrypt
set(GCC_OPTIONS "${GCC_OPTIONS}" -Wno-deprecated-declarations)

# compile options set on TpmConfiguration so it flows down to other libraries.
# TODO: Move to $<C_COMPILER_FRONTEND_VARIANT> when we use cmake >= 3.30.
target_compile_options(TpmConfiguration INTERFACE
    "$<$<STREQUAL:${CMAKE_C_COMPILER_FRONTEND_VARIANT},MSVC>:${MSVC_OPTIONS}>"
    "$<$<STREQUAL:${CMAKE_C_COMPILER_FRONTEND_VARIANT},GNU>:${GCC_OPTIONS}>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmBuildSwitches.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_CommandList.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_Common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_ErrorCodes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_Misc.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/VendorCommandList.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/CommandAttributeData_s_ccAttr.inl
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/CommandAttributeData_s_commandAttributes.inl
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration/VendorCommands)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/prototypes/Vendor_TCG_Test_fp.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration/VendorCommands/prototypes)


# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})

add_subdirectory(TpmVendorCommandHandlers)
