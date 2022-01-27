cmake_minimum_required(VERSION 3.21)
project(LMS_Hash_Based_Signatures)

set(EXEC_NAME hbslms)

set(CMAKE_CXX_STANDARD 14)

add_executable(${EXEC_NAME} main.cpp utils.cpp utils.h lmots.cpp lmots.h lms.h lms.cpp hss.h hss.cpp tests.cpp tests.h performancetest.cpp performancetest.h pershss.cpp pershss.h)

find_package(Threads REQUIRED)
target_link_libraries(${EXEC_NAME} Threads::Threads)

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

target_link_libraries(${EXEC_NAME} ${OPENSSL_LIBRARIES})
