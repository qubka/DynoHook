cmake_minimum_required(VERSION 3.25)
set(DYNOHOOK dynohook)
project(${DYNOHOOK})

set(DYNOHOOK_BUILD_TESTS ON)

# Force all compilers to use the correct C and C++ standard versions.
# Needed to allow for CheckCXXSourceCompiles to work correctly.
set(CMAKE_REQUIRED_FLAGS "-std=c++17 -std=c11")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Asmjit
set(ASMJIT_TEST OFF)
set(ASMJIT_EMBED OFF)
set(ASMJIT_STATIC ON)
set(ASMJIT_SANITIZE OFF)
add_subdirectory(src/external/asmjit)

# Capstone
set(CAPSTONE_BUILD_STATIC_RUNTIME OFF)
set(CAPSTONE_BUILD_STATIC ON)
set(CAPSTONE_BUILD_SHARED OFF)
set(CAPSTONE_BUILD_DIET OFF)
set(CAPSTONE_BUILD_TESTS OFF)
set(CAPSTONE_BUILD_CSTOOL OFF)
set(CAPSTONE_USE_DEFAULT_ALLOC ON)
set(CAPSTONE_ARCHITECTURE_DEFAULT ON)
set(CAPSTONE_INSTALL OFF)
add_subdirectory(src/external/capstone)
include_directories(src/external/capstone/include)

# DYNOHOOK
file(GLOB_RECURSE DYNOHOOK_SRC_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/dynohook/*.cpp")
file(GLOB_RECURSE DYNOHOOK_HDR_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/dynohook/*.hpp")
set(DYNOHOOK_PCH_FILE "src/pch.hpp")

add_library(${DYNOHOOK} ${DYNOHOOK_SRC_FILES} ${DYNOHOOK_HDR_FILES})

target_link_libraries(${DYNOHOOK} PUBLIC asmjit)
target_link_libraries(${DYNOHOOK} PUBLIC capstone-static)
target_precompile_headers(${DYNOHOOK} PUBLIC ${DYNOHOOK_PCH_FILE})
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(${DYNOHOOK} PUBLIC ENV64BIT)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_compile_definitions(${DYNOHOOK} PUBLIC ENV32BIT)
endif()

#######################

if (DYNOHOOK_BUILD_TESTS)
    set(DYNOHOOK_TEST_CONTENTS "")
    set(DYNOHOOK_TEST_HDR_FILES "")
    set(DYNOHOOK_TEST_ENTRIES "\nint main() {")

    file(GLOB_RECURSE DYNOHOOK_TEST_TEMPLATES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "tests/*.hpp.in")
    list(LENGTH DYNOHOOK_TEST_TEMPLATES DYNOHOOK_TEST_COUNT)
    math(EXPR DYNOHOOK_TEST_COUNT "${DYNOHOOK_TEST_COUNT}-1")

    macro (create_dynamic_hooks_test mode call obj)
        set(DYNOHOOK_TEST_CONV "${call}")
        set(DYNOHOOK_TEST_OBJECT "${obj}")
        set(DYNOHOOK_TEST_HEADER "${mode}/${obj}")
        foreach (i RANGE ${DYNOHOOK_TEST_COUNT})
            set(FILE "test${obj}${i}.hpp")
            set(DYNOHOOK_TEST_NAME "${obj}${i}")
            set(DYNOHOOK_TEST_NAMESPACE "test${obj}${i}")
            list(APPEND DYNOHOOK_TEST_HDR_FILES "tests/${FILE}")
            set(DYNOHOOK_TEST_ENTRIES "${DYNOHOOK_TEST_ENTRIES}\n\ttest${obj}${i}::test();")
            set(DYNOHOOK_TEST_CONTENTS "${DYNOHOOK_TEST_CONTENTS}\n#include \"${FILE}\"")
            configure_file("tests/test${i}.hpp.in" "tests/${FILE}" @ONLY)
        endforeach ()
    endmacro()

    if(WIN32)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            create_dynamic_hooks_test(x64 __fastcall x64MsStdcall)
        elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
            create_dynamic_hooks_test(x86 __cdecl x86MsCdecl)
            create_dynamic_hooks_test(x86 __stdcall x86MsStdcall)
            create_dynamic_hooks_test(x86 __fastcall x86MsFastcall)
        endif()
    endif()

    set(DYNOHOOK_TEST_ENTRIES "${DYNOHOOK_TEST_ENTRIES}\n\treturn 0;\n}")

    configure_file("tests/main.cpp.in" "tests/main.cpp" @ONLY)

    set(TEST_NAME dynohook_test)
    add_executable(${TEST_NAME} "tests/main.cpp" ${DYNOHOOK_TEST_HDR_FILES})
    include_directories(src/)
    target_link_libraries(${TEST_NAME} PUBLIC ${DYNOHOOK})
endif()