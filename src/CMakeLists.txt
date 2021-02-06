add_library(PCapPP pcap.hpp pcap.cpp)
add_library(PCapPP::PCapPP ALIAS PCapPP)

target_link_libraries(PCapPP PUBLIC PCap::PCap)

target_include_directories(PCapPP
  INTERFACE
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  )  

