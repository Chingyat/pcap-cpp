find_package(PkgConfig QUIET)

if (PkgConfig_FOUND)
   pkg_check_modules(PC_PCap QUIET libpcap)
endif()

find_path(PCap_INCLUDE_DIR NAMES pcap.h HINTS ${PC_PCap_INCLUDE_DIRS})

find_library(PCap_LIBRARY NAMES pcap HINTS ${PC_PCap_LIBRARIES})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(PCap
	DEFAULT_MSG
	PCap_LIBRARY
	PCap_INCLUDE_DIR
	)

if (PCap_FOUND AND NOT TARGET PCap::PCap)
   add_library(PCap::PCap UNKNOWN IMPORTED)
   set_target_properties(PCap::PCap
	PROPERTIES
	IMPORTED_LOCATION ${PCap_LIBRARY}
	INTERFACE_INCLUDE_DIRECTORIES ${PCap_INCLUDE_DIR}
	)
endif ()

set(PCap_INCLUDE_DIRS ${PCap_INCLUDE_DIR})
set(PCap_LIBRARIES ${PCap_LIBRARY})

mark_as_advanced(PCap_INCLUDE_DIR PCap_LIBRARY)
