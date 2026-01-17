cmake_minimum_required(VERSION 3.20)

project(CANoeDLL LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

set(DEMO_DIR "${PROJECT_SOURCE_DIR}/Demo")
set(ROOT_SRC_DIR "${PROJECT_SOURCE_DIR}/Sources")
set(ROOT_INC_DIR "${PROJECT_SOURCE_DIR}/Includes")
set(ROOT_EXTINC_DIR "${PROJECT_SOURCE_DIR}/ExtInclude")
set(ROOT_EXTLIB_DIR "${PROJECT_SOURCE_DIR}/ExtLib")

if(NOT EXISTS "${ROOT_SRC_DIR}/crypto_canoedll.cpp")
  if(EXISTS "${DEMO_DIR}/Sources/capldll.cpp")
    file(MAKE_DIRECTORY "${ROOT_SRC_DIR}")
    file(COPY "${DEMO_DIR}/Sources/capldll.cpp" DESTINATION "${ROOT_SRC_DIR}")
    file(RENAME
      "${ROOT_SRC_DIR}/capldll.cpp"
      "${ROOT_SRC_DIR}/crypto_canoedll.cpp")
  else()
    message(FATAL_ERROR "Missing Sources/crypto_canoedll.cpp. Copy from Demo/Sources first.")
  endif()
endif()

if(NOT EXISTS "${ROOT_SRC_DIR}/capldll.def")
  if(EXISTS "${DEMO_DIR}/Sources/capldll.def")
    file(MAKE_DIRECTORY "${ROOT_SRC_DIR}")
    file(COPY "${DEMO_DIR}/Sources/capldll.def" DESTINATION "${ROOT_SRC_DIR}")
  else()
    message(FATAL_ERROR "Missing Sources/capldll.def. Copy from Demo/Sources first.")
  endif()
endif()

if(NOT EXISTS "${ROOT_INC_DIR}/cdll.h")
  if(EXISTS "${DEMO_DIR}/Includes/cdll.h")
    file(MAKE_DIRECTORY "${ROOT_INC_DIR}")
    file(COPY "${DEMO_DIR}/Includes/" DESTINATION "${ROOT_INC_DIR}")
  else()
    message(FATAL_ERROR "Missing Includes. Copy from Demo/Includes first.")
  endif()
endif()

if(NOT EXISTS "${ROOT_EXTINC_DIR}/rsa.h")
  if(EXISTS "${DEMO_DIR}/ExtInclude/rsa.h")
    file(MAKE_DIRECTORY "${ROOT_EXTINC_DIR}")
    file(COPY "${DEMO_DIR}/ExtInclude/" DESTINATION "${ROOT_EXTINC_DIR}")
  else()
    message(FATAL_ERROR "Missing ExtInclude. Copy from Demo/ExtInclude first.")
  endif()
endif()

if(NOT EXISTS "${ROOT_EXTLIB_DIR}/cryptlib32.lib")
  if(EXISTS "${DEMO_DIR}/ExtLib/cryptlib32.lib")
    file(MAKE_DIRECTORY "${ROOT_EXTLIB_DIR}")
    file(COPY "${DEMO_DIR}/ExtLib/cryptlib32.lib" DESTINATION "${ROOT_EXTLIB_DIR}")
  else()
    message(FATAL_ERROR "Missing ExtLib/cryptlib32.lib. Copy from Demo/ExtLib first.")
  endif()
endif()

if(NOT EXISTS "${ROOT_EXTLIB_DIR}/cryptlib64.lib")
  if(EXISTS "${DEMO_DIR}/ExtLib/cryptlib64.lib")
    file(MAKE_DIRECTORY "${ROOT_EXTLIB_DIR}")
    file(COPY "${DEMO_DIR}/ExtLib/cryptlib64.lib" DESTINATION "${ROOT_EXTLIB_DIR}")
  endif()
endif()

add_library(capldll SHARED
  Sources/crypto_canoedll.cpp
)

target_include_directories(capldll PRIVATE
  ${PROJECT_SOURCE_DIR}/ExtInclude
  ${PROJECT_SOURCE_DIR}/Includes
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(CRYPTLIB_PATH "${PROJECT_SOURCE_DIR}/ExtLib/cryptlib64.lib")
else()
  set(CRYPTLIB_PATH "${PROJECT_SOURCE_DIR}/ExtLib/cryptlib32.lib")
endif()

target_link_libraries(capldll PRIVATE
  ${CRYPTLIB_PATH}
)

if(MSVC)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_options(capldll PRIVATE
      "/DEF:${PROJECT_SOURCE_DIR}/Sources/capldll_x64.def"
      "/MAP"
    )
  else()
    target_link_options(capldll PRIVATE
      "/DEF:${PROJECT_SOURCE_DIR}/Sources/capldll.def"
      "/MAP"
    )
  endif()
  target_compile_options(capldll PRIVATE "/utf-8")
  target_compile_definitions(capldll PRIVATE
    $<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=0>
    $<$<CONFIG:Debug>:_HAS_ITERATOR_DEBUGGING=0>
  )
endif()

add_executable(capldll_selftest
  Tests/capldll_selftest.cpp
  Sources/crypto_canoedll.cpp
)

target_include_directories(capldll_selftest PRIVATE
  ${PROJECT_SOURCE_DIR}/ExtInclude
  ${PROJECT_SOURCE_DIR}/Includes
)

target_link_libraries(capldll_selftest PRIVATE
  ${CRYPTLIB_PATH}
)

if(MSVC)
  target_compile_options(capldll_selftest PRIVATE "/utf-8")
endif()

set_target_properties(capldll_selftest PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

set_target_properties(capldll PROPERTIES
  OUTPUT_NAME "crypto_canoedll"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
