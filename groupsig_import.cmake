set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--allow-multiple-definition")

target_link_libraries(${TA_BINARY}
  kty04
  cpy06
  bbs04
  gl19
  ps16
  klap20
  dl21
  dl21seq
  groupsig-static
  groupsig-demos
  sys
  math
  base64
  misc
  hash
  gcrypto
  msg
  pbcext
  logger
  big
  mclbn384_256
  mcl
  ssl
  crypto
  mondrianl
)

include_directories("${PROJECT_SOURCE_DIR}/modules/libgroupsig/src")
