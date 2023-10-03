cmake_minimum_required(VERSION 3.9 FATAL_ERROR)
set(PROJECT_NAME dynohook)
project(${PROJECT_NAME})

set(DYNOHOOK_BUILD_TESTS OFF)
set(DYNOHOOK_BUILD_64 ON)

# Force all compilers to use the correct C and C++ standard versions.
# Needed to allow for CheckCXXSourceCompiles to work correctly.
set(CMAKE_REQUIRED_FLAGS "-std=c++20 -std=c11")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if (MSVC)
    #set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /INCREMENTAL:NO")
else ()
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra -Werror -Wconversion")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif ()

if (DYNOHOOK_BUILD_32)
    if (MSVC)
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            message(SEND_ERROR "You need to specify correct MSVC 32-bit compiler!" )
        endif ()
    else ()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
    endif ()
endif ()

# Asmjit
set(ASMJIT_TEST OFF)
set(ASMJIT_EMBED OFF)
set(ASMJIT_STATIC ON)
set(ASMJIT_SANITIZE OFF)
set(ASMTK_TEST OFF)
set(ASMTK_EMBED OFF)
set(ASMTK_STATIC ON)
#add_subdirectory(src/external/asmjit)
add_subdirectory(src/external/asmtk)

# Zydis
set(ZYDIS_BUILD_SHARED_LIB OFF)
set(ZYDIS_BUILD_EXAMPLES OFF)
set(ZYDIS_BUILD_TOOLS OFF)
set(ZYDIS_BUILD_MAN OFF)
set(ZYDIS_BUILD_DOXYGEN OFF)
set(ZYDIS_FUZZ_AFL_FAST OFF)
set(ZYDIS_LIBFUZZER OFF)
add_subdirectory(src/external/zydis)

# DYNOHOOK
file(GLOB_RECURSE DYNOHOOK_SRC_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/dynohook/*.cpp")
file(GLOB_RECURSE DYNOHOOK_HDR_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/dynohook/*.h")
set(DYNOHOOK_PCH_FILE "src/pch.h")

add_executable(${PROJECT_NAME} ${DYNOHOOK_SRC_FILES} ${DYNOHOOK_HDR_FILES})

#target_link_libraries(${PROJECT_NAME} PRIVATE asmjit)
target_link_libraries(${PROJECT_NAME} PRIVATE asmtk)
target_link_libraries(${PROJECT_NAME} PRIVATE Zydis)
target_include_directories(${PROJECT_NAME} PUBLIC "src")
target_precompile_headers(${PROJECT_NAME} PRIVATE ${DYNOHOOK_PCH_FILE})

if (DYNOHOOK_BUILD_32)
    if (NOT MSVC)
        set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
    endif ()
    message(STATUS "Excluding 64bit library paths from search.")
    set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS OFF)
    set(DYNOHOOK_ARCH i686)
elseif (DYNOHOOK_BUILD_64)
    if (NOT MSVC)
        set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS  "-m64" LINK_FLAGS "-m64")
    endif ()
    set(DYNOHOOK_ARCH amd64)
else ()
    set(DYNOHOOK_ARCH amd64)
endif ()

#######################