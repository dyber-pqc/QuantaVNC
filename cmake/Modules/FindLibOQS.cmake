#[=======================================================================[.rst:
FindLibOQS
----------

Find the Open Quantum Safe (liboqs) library

Result variables
^^^^^^^^^^^^^^^^

This module will set the following variables if found:

``OQS_INCLUDE_DIRS``
  where to find oqs/oqs.h, etc.
``OQS_LIBRARIES``
  the libraries to link against to use liboqs.
``OQS_FOUND``
  TRUE if found

#]=======================================================================]

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_OQS QUIET liboqs)
endif()

find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h
  HINTS
    ${PC_OQS_INCLUDE_DIRS}
)
mark_as_advanced(OQS_INCLUDE_DIR)

find_library(OQS_LIBRARY NAMES oqs liboqs
  HINTS
    ${PC_OQS_LIBRARY_DIRS}
)
mark_as_advanced(OQS_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibOQS
  REQUIRED_VARS
    OQS_LIBRARY OQS_INCLUDE_DIR
)

if(LibOQS_FOUND)
  set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
  set(OQS_LIBRARIES ${OQS_LIBRARY})
  set(OQS_FOUND TRUE)
endif()
