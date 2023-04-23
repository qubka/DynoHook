cmake_minimum_required(VERSION 3.9 FATAL_ERROR)
set(PROJECT_NAME dynohook)
project(${PROJECT_NAME})

set(DYNOHOOK_BUILD_TESTS ON)
set(DYNOHOOK_BUILD_64 ON)

# Force all compilers to use the correct C and C++ standard versions.
# Needed to allow for CheckCXXSourceCompiles to work correctly.
set(CMAKE_REQUIRED_FLAGS "-std=c++17 -std=c11")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if (MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /INCREMENTAL:NO")
else ()
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra -Werror -Wconversion")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
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
add_subdirectory(src/external/asmjit)

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

add_library(${PROJECT_NAME} ${DYNOHOOK_SRC_FILES} ${DYNOHOOK_HDR_FILES})

target_link_libraries(${PROJECT_NAME} PRIVATE asmjit)
target_link_libraries(${PROJECT_NAME} PRIVATE Zydis)
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

if (DYNOHOOK_BUILD_TESTS)
    set(DYNOHOOK_TEST_CONTENTS "")
    set(DYNOHOOK_TEST_HDR_FILES "")
    set(DYNOHOOK_TEST_ENTRIES "\nint main() {")

    macro (create_dyno_hooks_test mode call obj list)
        # Generate required tests
        string(REPLACE " " ";" INDEX_LIST ${list})
        foreach (i ${INDEX_LIST})
            # Append generated file to header list
            set(FILE "test${obj}${i}.h")
            list(APPEND DYNOHOOK_TEST_HDR_FILES "${CMAKE_CURRENT_BINARY_DIR}/tests/${FILE}")

            # Pass data into configuration file
            set(DYNOHOOK_TEST_CONV "${call}")
            set(DYNOHOOK_TEST_OBJECT "${obj}")
            set(DYNOHOOK_TEST_HEADER "${mode}/${obj}")
            set(DYNOHOOK_TEST_NAME "${obj}${i}")
            set(DYNOHOOK_TEST_NAMESPACE "test${DYNOHOOK_TEST_NAME}")
            set(DYNOHOOK_TEST_ENTRIES "${DYNOHOOK_TEST_ENTRIES}\n\t${DYNOHOOK_TEST_NAMESPACE}::test();")
            set(DYNOHOOK_TEST_CONTENTS "${DYNOHOOK_TEST_CONTENTS}\n#include \"${FILE}\"")

            # Generate test file
            configure_file("tests/test${i}.hpp.in" "tests/${FILE}" @ONLY)
        endforeach ()
    endmacro ()

    if (WIN32)

        if (${DYNOHOOK_ARCH} MATCHES "amd64")
            create_dyno_hooks_test(x64 /*MS_ABI*/ x64MsFastcall "0 1 2 3 4 5 6 7 8")
        else ()
            create_dyno_hooks_test(x86 DYNO_CDECL x86MsCdecl "0 1 2 3 4 5 6 7 8")
            create_dyno_hooks_test(x86 DYNO_STDCALL x86MsStdcall "0 1 2 3 4 5 6 7 8")
            create_dyno_hooks_test(x86 DYNO_FASTCALL x86MsFastcall "0 1 2 3 4 5 6 7 8")
            create_dyno_hooks_test(x86 DYNO_THISCALL x86MsThiscall "6 8")
        endif ()
    else ()
        if (${DYNOHOOK_ARCH} MATCHES "amd64")
            create_dyno_hooks_test(x64 /*SYSV_ABI*/ x64SystemVcall "0 1 2 3 4 5 6 7 8")
        else ()
            create_dyno_hooks_test(x86 DYNO_CDECL x86GccCdecl "0 1 2 3 4 5 6 7 8")
            create_dyno_hooks_test(x86 DYNO_THISCALL x86GccThiscall "6 8")
        endif ()
    endif ()

    set(DYNOHOOK_TEST_ENTRIES "${DYNOHOOK_TEST_ENTRIES}\n\treturn 0;\n}")

    configure_file("tests/main.cpp.in" "tests/main.cpp" @ONLY)

    set(TEST_NAME dynohook_test)
    add_executable(${TEST_NAME} "${CMAKE_CURRENT_BINARY_DIR}/tests/main.cpp" ${DYNOHOOK_TEST_HDR_FILES})
    if (MSVC)
        set_property(TARGET ${TEST_NAME} APPEND_STRING PROPERTY LINK_FLAGS " /INCREMENTAL:NO")
    endif ()
    include_directories(src/)
    target_link_libraries(${TEST_NAME} PUBLIC ${PROJECT_NAME})
    target_precompile_headers(${TEST_NAME} PRIVATE ${DYNOHOOK_PCH_FILE})
endif ()