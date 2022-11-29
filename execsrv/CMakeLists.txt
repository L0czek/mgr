cmake_minimum_required(VERSION 3.3)
project(execsrv)

if (NOT ${CMAKE_BUIDL_TYPE})
    set(CMAKE_BUIDL_TYPE "Debug")
endif ()

add_executable(srv
    src/main.cc
)

target_link_libraries(srv pthread)
