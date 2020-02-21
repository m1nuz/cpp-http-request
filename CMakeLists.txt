cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(cpp_http_request VERSION 0.1.1)

include(FetchContent)
include(CTest)

set(APP_NAME cpp_http_request_tests)
set(LIB_NAME cpp_http_request)
set(SHARED_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(OpenSSL)
add_library(${LIB_NAME} INTERFACE)

target_include_directories(${LIB_NAME} INTERFACE include/)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.8.1
)

FetchContent_GetProperties(googletest)
if(NOT googletest_POPULATED)
    FetchContent_Populate(googletest)
    add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR})
endif()

FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.7.3
)

if(NOT json_POPULATED)
    FetchContent_Populate(json)
    set(json_INCLUDE_DIR ${json_SOURCE_DIR}/include)
endif()

enable_testing()

set(SOURCES
    src/http_request_tests.cc
    src/https_request_tests.cc
    )
add_executable(${APP_NAME} ${SOURCES} ${HEADERS})

if(OPENSSL_FOUND)
    target_compile_definitions(${APP_NAME} PUBLIC CPP_HTTP_REQUEST_SUPPORT_SSL)
endif()

target_include_directories(${APP_NAME} PUBLIC
    ${SHARED_INCLUDE_DIR}
    ${EXTERNAL_INCLUDE_DIR}
    ${json_INCLUDE_DIR}
)

set_target_properties(${APP_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    )

target_compile_options(${APP_NAME} PUBLIC
    -pthread
    -pedantic
    -Wall
    -Wextra
    -Wshadow
    )

add_test(UnitTests ${APP_NAME})

target_link_libraries(${APP_NAME} PUBLIC
    ${LIB_NAME}
    gtest
    gmock
    gtest_main
    OpenSSL::SSL)
