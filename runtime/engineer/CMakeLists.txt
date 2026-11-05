cmake_minimum_required(VERSION 3.28)
project(omk_engineer LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions> $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)

set(CXX_ROOT "${OMK_CXX}/prefab/modules/cxx")
add_library(cxx::cxx STATIC IMPORTED GLOBAL)
set_target_properties(cxx::cxx PROPERTIES
    IMPORTED_LOCATION "${CXX_ROOT}/libs/android.${ANDROID_ABI}/libcxx.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CXX_ROOT}/include"
    INTERFACE_COMPILE_OPTIONS "-nostdinc++")
include("${CXX_ROOT}/include/prefab/cmake-config.cmake")
# LSPlant's find_package imports the target above through this config.
set(cxx_DIR "${CMAKE_CURRENT_LIST_DIR}/cxx")
set(LSPLANT_STANDALONE ON CACHE BOOL "" FORCE)
set(LSPLANT_BUILD_SHARED OFF CACHE BOOL "" FORCE)
add_subdirectory("${OMK_LSPLANT}/lsplant/src/main/jni" lsplant)
add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES
    IMPORTED_LOCATION "${OMK_DOBBY}/prefab/modules/dobby/libs/android.${ANDROID_ABI}/libdobby.a"
    INTERFACE_INCLUDE_DIRECTORIES "${OMK_DOBBY}/prefab/modules/dobby/include")
add_library(omk_engineer SHARED bridge.cpp)
target_include_directories(omk_engineer PRIVATE "${OMK_GENERATED}")
target_link_libraries(omk_engineer PRIVATE lsplant_static dobby cxx::cxx c++abi dl log)
target_compile_options(omk_engineer PRIVATE -fvisibility=hidden -Wall -Wextra -Werror)
target_link_options(omk_engineer PRIVATE -Wl,-z,max-page-size=16384)
add_custom_command(TARGET omk_engineer POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:omk_engineer>)
