cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

if(POLICY CMP0092)
    cmake_policy(SET CMP0092 NEW) # Don't add -W3 warning level by default.
endif()

project(dynohook)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    set(DYNOHOOK_OS "windows")
elseif(APPLE)
    set(DYNOHOOK_OS "macos")
elseif(UNIX)
    set(DYNOHOOK_OS "linux")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DYNOHOOK_BUILD_64 ON)
	set(DYNOHOOK_BUILD_PREFIX "x64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(DYNOHOOK_BUILD_32 ON)
	set(DYNOHOOK_BUILD_PREFIX "x86")
endif()

if(DYNOHOOK_BUILD_32)
    if(NOT MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
    endif()
endif()

include(git.cmake)

#
# Options
#

option(DYNOHOOK_BUILD_DLL "Build dll & lib instead of tests" OFF)

option(DYNOHOOK_BUILD_SHARED_LIB "Build dynohook as shared libary" OFF)
option(DYNOHOOK_BUILD_SHARED_ASMTK "Build asmtk as shared libary" OFF)
option(DYNOHOOK_BUILD_SHARED_ASMJIT "Build asmjit as shared libary" ${DYNOHOOK_BUILD_SHARED_ASMTK})
option(DYNOHOOK_BUILD_SHARED_ZYDIS "Build zydis as shared libary" OFF)

option(DYNOHOOK_USE_EXTERNAL_ASMTK "Use external asmtk libary" OFF)
option(DYNOHOOK_USE_EXTERNAL_ASMJIT "Use external asmjit libary" ${DYNOHOOK_USE_EXTERNAL_ASMTK})
option(DYNOHOOK_USE_EXTERNAL_ZYDIS "Use external zydis libary" OFF)

if(MSVC)
    option(DYNOHOOK_BUILD_STATIC_RUNTIME "Use static runtime" ON)
endif()

option(DYNOHOOK_FEATURE_DETOURS "Implement detour functionality" ON)
option(DYNOHOOK_FEATURE_VIRTUALS "Implement virtual table hooking functionality" ON)
option(DYNOHOOK_FEATURE_LOGGING "Implement logging functionality" On)

#
# Catch2
#

if(NOT DYNOHOOK_BUILD_DLL)
	add_subdirectory(catch2)
	
	if(MSVC)
        if(DYNOHOOK_BUILD_STATIC_RUNTIME)
            set_target_properties(Catch2 PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        else()
            set_target_properties(Catch2 PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endif()
endif()

#
# ASMTK/ASMJIT
#

function(add_asmjit_properties)
    if(MSVC)
        if(ASMJIT_STATIC)
            set_target_properties(asmjit PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        else()
            set_target_properties(asmjit PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endif()
endfunction()

if(DYNOHOOK_FEATURE_DETOURS AND NOT DYNOHOOK_USE_EXTERNAL_ASMTK)
    if(NOT DYNOHOOK_USE_EXTERNAL_ASMJIT)
        set(ASMJIT_DIR "${PROJECT_SOURCE_DIR}/asmjit")
    endif()

    if(DYNOHOOK_BUILD_SHARED_ASMTK)
        set(ASMTK_STATIC OFF CACHE BOOL "")
        set(ASMJIT_STATIC OFF CACHE BOOL "")
    else()
        set(ASMTK_STATIC ON CACHE BOOL "")
        set(ASMJIT_STATIC ON CACHE BOOL "")
    endif()

    add_subdirectory(asmtk)
    add_asmjit_properties()

    if(MSVC)
        if(DYNOHOOK_BUILD_STATIC_RUNTIME)
            set_target_properties(asmtk PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        else()
            set_target_properties(asmtk PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endif()

endif()

#
# Zydis
#

if(NOT DYNOHOOK_USE_EXTERNAL_ZYDIS)
    set(ZYDIS_BUILD_SHARED_LIB ${DYNOHOOK_BUILD_SHARED_ZYDIS} CACHE BOOL "")
    set(ZYCORE_BUILD_SHARED_LIB ${DYNOHOOK_BUILD_SHARED_ZYDIS} CACHE BOOL "")
    set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "")
    set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "")
    set(ZYDIS_BUILD_MAN OFF CACHE BOOL "")
    set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "")
    set(ZYDIS_FUZZ_AFL_FAST OFF CACHE BOOL "")
    set(ZYDIS_LIBFUZZER OFF CACHE BOOL "")

    add_subdirectory(zydis/dependencies/zycore)
    add_subdirectory(zydis)

    if(MSVC)
        if(DYNOHOOK_BUILD_STATIC_RUNTIME)
            set_target_properties(Zycore PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
            set_target_properties(Zydis PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        else()
            set_target_properties(Zycore PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
            set_target_properties(Zydis PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endif()
endif()

#
# Dynohook
#

if(DYNOHOOK_BUILD_DLL)
    if(DYNOHOOK_BUILD_SHARED_LIB)
        add_library(${PROJECT_NAME} SHARED)
        set_target_properties(${PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    else()
        add_library(${PROJECT_NAME} STATIC)
    endif()
else()
    add_executable(${PROJECT_NAME})
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE git-info)

if(MSVC)
    if(DYNOHOOK_BUILD_STATIC_RUNTIME)
        set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()
endif()

if(DYNOHOOK_BUILD_32)
    if(NOT MSVC)
        set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
    endif()
    message(STATUS "Excluding 64bit library paths from search.")
    set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS OFF)
elseif(DYNOHOOK_BUILD_64)
    if(NOT MSVC)
        set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS  "-m64" LINK_FLAGS "-m64")
    endif()
endif()

target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
        INTERFACE
        $<INSTALL_INTERFACE:include>
        )

#Core
set(DYNOHOOK_CORE_HEADERS
		${PROJECT_SOURCE_DIR}/dynohook/convention.h
		${PROJECT_SOURCE_DIR}/dynohook/core.h
		${PROJECT_SOURCE_DIR}/dynohook/fb_allocator.h
		${PROJECT_SOURCE_DIR}/dynohook/hook.h
		${PROJECT_SOURCE_DIR}/dynohook/instruction.h
		${PROJECT_SOURCE_DIR}/dynohook/manager.h
		${PROJECT_SOURCE_DIR}/dynohook/mem_accessor.h
        ${PROJECT_SOURCE_DIR}/dynohook/mem_protector.h
		${PROJECT_SOURCE_DIR}/dynohook/range_allocator.h
		${PROJECT_SOURCE_DIR}/dynohook/registers.h
		${PROJECT_SOURCE_DIR}/dynohook/log.h
        ${PROJECT_SOURCE_DIR}/dynohook/os.h
        ${PROJECT_SOURCE_DIR}/dynohook/platform.h
        ${PROJECT_SOURCE_DIR}/dynohook/prot.h

        ${PROJECT_SOURCE_DIR}/dynohook/tests/effect_tracker.h
        ${PROJECT_SOURCE_DIR}/dynohook/tests/stack_canary.h
        )
install(FILES ${DYNOHOOK_CORE_HEADERS} DESTINATION include/dynohook)


target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/dynohook/convention.cpp
		${PROJECT_SOURCE_DIR}/dynohook/core.cpp
		${PROJECT_SOURCE_DIR}/dynohook/fb_allocator.cpp
		${PROJECT_SOURCE_DIR}/dynohook/hook.cpp
		${PROJECT_SOURCE_DIR}/dynohook/instruction.cpp
		${PROJECT_SOURCE_DIR}/dynohook/manager.cpp
		${PROJECT_SOURCE_DIR}/dynohook/mem_accessor.cpp
		${PROJECT_SOURCE_DIR}/dynohook/mem_protector.cpp
		${PROJECT_SOURCE_DIR}/dynohook/range_allocator.cpp
		${PROJECT_SOURCE_DIR}/dynohook/registers.cpp
		${PROJECT_SOURCE_DIR}/dynohook/log.cpp

        ${PROJECT_SOURCE_DIR}/dynohook/tests/effect_tracker.cpp
        ${PROJECT_SOURCE_DIR}/dynohook/tests/stack_canary.cpp
		)

target_precompile_headers(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/dynohook/pch.h)

if(NOT DYNOHOOK_BUILD_DLL)
	target_compile_options(${PROJECT_NAME} PRIVATE
		$<$<BOOL:${UNIX}>:-fpermissive>
	)
endif()

#Zydis
if(DYNOHOOK_USE_EXTERNAL_ZYDIS)
    find_package(zydis REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC Zydis::Zydis)
else()
    target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:Zydis>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/zydis/include>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/zydis/dependencies/zycore/include>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/zydis>)
endif()

target_sources(${PROJECT_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/dynohook/disassembler.cpp")
install(FILES ${PROJECT_SOURCE_DIR}/dynohook/disassembler.h DESTINATION include/dynohook)

function(link_asmjit)
    if(DYNOHOOK_USE_EXTERNAL_ASMJIT)
        find_package(asmjit REQUIRED)
        target_link_libraries(${PROJECT_NAME} PRIVATE asmjit::asmjit)
    else()
        target_link_libraries(${PROJECT_NAME} PRIVATE $<BUILD_INTERFACE:asmjit>)
        target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${ASMJIT_SRC}>")
        if(MSVC)
            target_compile_options(asmjit PUBLIC /wd5054)
        elseif(MINGW)
            target_compile_options(asmjit PUBLIC -Wno-deprecated-enum-enum-conversion)
        else()
            target_compile_options(asmjit PUBLIC -Wno-deprecated-anon-enum-enum-conversion)
        endif()
    endif()
endfunction()

#Feature/Detours
if(DYNOHOOK_FEATURE_DETOURS)
    link_asmjit()

    if(DYNOHOOK_USE_EXTERNAL_ASMTK)
        find_package(asmtk REQUIRED)
        target_link_libraries(${PROJECT_NAME} PRIVATE asmjit::asmtk)
    else()
        target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:asmtk>)
        target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${ASMTK_SRC}>")
    endif()

	set(DYNOHOOK_DETOUR_HEADERS
		${PROJECT_SOURCE_DIR}/dynohook/detours/detour.h
		${PROJECT_SOURCE_DIR}/dynohook/detours/nat_detour.h
		${PROJECT_SOURCE_DIR}/dynohook/detours/${DYNOHOOK_BUILD_PREFIX}_detour.h)

	install(FILES ${DYNOHOOK_DETOUR_HEADERS} DESTINATION include/dynohook/detours)

	target_sources(${PROJECT_NAME} PRIVATE 
		${PROJECT_SOURCE_DIR}/dynohook/detours/detour.cpp
		${PROJECT_SOURCE_DIR}/dynohook/detours/${DYNOHOOK_BUILD_PREFIX}_detour.cpp
	)

	# only build tests if making exe
	if(NOT DYNOHOOK_BUILD_DLL)
        if(DYNOHOOK_BUILD_64)
            target_sources(${PROJECT_NAME} PRIVATE
                ${PROJECT_SOURCE_DIR}/tests/test_detour_translation_x64.cpp
                ${PROJECT_SOURCE_DIR}/tests/test_detour_scheme_x64.cpp
                ${PROJECT_SOURCE_DIR}/tests/test_detour_notd_x64.cpp
                ${PROJECT_SOURCE_DIR}/tests/test_detour_x64.cpp)
        elseif(DYNOHOOK_BUILD_32)
            target_sources(${PROJECT_NAME} PRIVATE
                    ${PROJECT_SOURCE_DIR}/tests/test_detour_x86.cpp)
        endif()
	endif()
endif()

#Feature/Virtuals
if(DYNOHOOK_FEATURE_VIRTUALS)
	set(DYNOHOOK_VIRTUAL_HEADERS
		${PROJECT_SOURCE_DIR}/dynohook/virtuals/vtable.h
		${PROJECT_SOURCE_DIR}/dynohook/virtuals/vhook.h)
	install(FILES ${DYNOHOOK_VIRTUAL_HEADERS} DESTINATION include/dynohook/virtuals)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/dynohook/virtuals/vtable.cpp
		${PROJECT_SOURCE_DIR}/dynohook/virtuals/vhook.cpp)

	# only build tests if making exe
	if(NOT DYNOHOOK_BUILD_DLL)
		target_sources(${PROJECT_NAME} PRIVATE
			${PROJECT_SOURCE_DIR}/tests/test_virtual.cpp)
	endif()
endif()

#Feature/CallConv
if(DYNOHOOK_BUILD_64)
	set(DYNOHOOK_CALLCONV_HEADERS
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x64_ms_fastcall.h
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x64_systemV_call.h)
	install(FILES ${DYNOHOOK_CALLCONV_HEADERS} DESTINATION include/dynohook/conventions)

	target_sources(${PROJECT_NAME} PRIVATE
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x64_ms_fastcall.cpp
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x64_systemV_call.cpp)
elseif(DYNOHOOK_BUILD_32)
	set(DYNOHOOK_CALLCONV_HEADERS
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_gcc_cdecl.h
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_gcc_thiscall.h
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_cdecl.h
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_fastcall.h
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_stdcall.h
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_thiscall.h)
	install(FILES ${DYNOHOOK_CALLCONV_HEADERS} DESTINATION include/dynohook/conventions)

	target_sources(${PROJECT_NAME} PRIVATE
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_cdecl.cpp
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_fastcall.cpp
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_stdcall.cpp
            ${PROJECT_SOURCE_DIR}/dynohook/conventions/x86_ms_thiscall.cpp)
endif()

#Feature/Logging
if(DYNOHOOK_FEATURE_LOGGING)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        DYNO_LOGGING
        DYNO_COMPILED_COMPILER="${CMAKE_CXX_COMPILER}"
        DYNO_COMPILED_SYSTEM="${CMAKE_SYSTEM}"
        DYNO_COMPILED_GENERATOR="${CMAKE_GENERATOR}")
endif()

#Tests
if(NOT DYNOHOOK_BUILD_DLL)
	target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:Catch2>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/catch2/src/catch2>)
	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/tests/main_tests.cpp
	    ${PROJECT_SOURCE_DIR}/tests/test_disassembler.cpp
		${PROJECT_SOURCE_DIR}/tests/${DYNOHOOK_OS}/test_mem_protector.cpp)
endif()

#
# Install
#

configure_package_config_file(
		"${PROJECT_NAME}-config.cmake.in"
		"${PROJECT_NAME}-config.cmake"
	INSTALL_DESTINATION
        "lib/${PROJECT_NAME}"
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
    DESTINATION
        "lib/${PROJECT_NAME}"
)

install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    RUNTIME DESTINATION "bin"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
)

install(
    EXPORT
        ${PROJECT_NAME}-targets
    NAMESPACE
        ${PROJECT_NAME}::
    DESTINATION
        "lib/${PROJECT_NAME}"
)