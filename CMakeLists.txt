cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(cpp_http_request VERSION 0.1.1)

set(APP_NAME cpp_http_request_tests)
set(LIB_NAME cpp_http_request)

add_library(${LIB_NAME} INTERFACE)
target_include_directories(${LIB_NAME} INTERFACE include/)

set(SOURCES
    src/http_request_tests.cc
    )
add_executable(${APP_NAME} ${SOURCES} ${HEADERS})

target_include_directories(${APP_NAME} PUBLIC
    ${SHARED_INCLUDE_DIR}
    ${EXTERNAL_INCLUDE_DIR}
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

target_link_libraries(${APP_NAME} PUBLIC ${LIB_NAME})
