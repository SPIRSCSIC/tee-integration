include(ExternalProject)

# Add libgroupsig as an external project
ExternalProject_Add(libgroupsig
  SOURCE_DIR ${CMAKE_SOURCE_DIR}/modules/libgroupsig/tee
  BINARY_DIR ${CMAKE_BINARY_DIR}/libgroupsig-build
  CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  INSTALL_COMMAND ""
)
include_directories(${CMAKE_SOURCE_DIR}/modules/libgroupsig/src/include)
link_directories(${CMAKE_BINARY_DIR}/libgroupsig-build/lib)
include_directories(${CMAKE_BINARY_DIR}/libgroupsig-build/external/include)
link_directories(${CMAKE_BINARY_DIR}/libgroupsig-build/external/lib)

# Add mondrian as an external project
ExternalProject_Add(mondrian
  SOURCE_DIR ${CMAKE_SOURCE_DIR}/modules/mondrian/tee
  BINARY_DIR ${CMAKE_BINARY_DIR}/mondrian-build
  CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  INSTALL_COMMAND ""
)
include_directories(${CMAKE_SOURCE_DIR}/modules/mondrian/src)
link_directories(${CMAKE_BINARY_DIR}/mondrian-build)
