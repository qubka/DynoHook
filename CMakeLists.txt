cmake_minimum_required(VERSION 3.9 FATAL_ERROR)
project(dynohook)

# Force all compilers to use the correct C and C++ standard versions.
# Needed to allow for CheckCXXSourceCompiles to work correctly.
set(CMAKE_REQUIRED_FLAGS "-std=c++20 -std=c11")
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

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD_REQUIRED ON)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_EXTENSIONS ON)

if(MSVC)
    if(DYNOHOOK_BUILD_STATIC_RUNTIME)
        set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set_target_properties(${PROJECT_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()

    if(MSVC)
        set(COMPILE_FLAGS_PLH "/W4 /Z7")
        if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            set(COMPILE_FLAGS_PLH "/MP ${COMPILE_FLAGS_PLH}")
        endif()

        set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${COMPILE_FLAGS_PLH})
        target_link_libraries(${PROJECT_NAME} PRIVATE optimized -DEBUG)
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

		${PROJECT_SOURCE_DIR}/dynohook/os.h
		${PROJECT_SOURCE_DIR}/dynohook/platform.h
		${PROJECT_SOURCE_DIR}/dynohook/prot.h
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
		)

target_precompile_headers(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/dynohook/pch.h)

if(NOT DYNOHOOK_BUILD_DLL)
	target_compile_options(${PROJECT_NAME} PRIVATE
		$<$<BOOL:${UNIX}>:-fpermissive>
	)
endif()

#Zydis
if(DYNOHOOK_USE_EXTERNAL_ZYDIS)
    find_library(ZYDIS_LIBRARY NAMES zydis)
    find_library(ZYCORE_LIBRARY NAMES zycore)
    find_path(ZYDIS_INCLUDE_DIR NAMES zydis/zydis.h)
    find_path(ZYCORE_INCLUDE_DIR NAMES zycore/zycore.h)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${ZYDIS_LIBRARY})
    target_link_libraries(${PROJECT_NAME} PUBLIC ${ZYCORE_LIBRARY})
    target_include_directories(${PROJECT_NAME} PUBLIC ${ZYDIS_INCLUDE_DIR})
    target_include_directories(${PROJECT_NAME} PUBLIC ${ZYCORE_INCLUDE_DIR})
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
        find_library(ASMJIT_LIBRARY NAMES asmjit)
        find_path(ASMJIT_INCLUDE_DIR NAMES asmjit/asmjit.h)
        target_link_libraries(${PROJECT_NAME} PRIVATE ${ASMJIT_LIBRARY})
        target_include_directories(${PROJECT_NAME} PUBLIC ${ASMJIT_INCLUDE_DIR})
    else()
        target_link_libraries(${PROJECT_NAME} PRIVATE $<BUILD_INTERFACE:asmjit>)
        target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${ASMJIT_SRC}>")
    endif()
endfunction()

#Feature/Detours
if(DYNOHOOK_FEATURE_DETOURS)
    link_asmjit()

    if(DYNOHOOK_USE_EXTERNAL_ASMTK)
        find_library(ASMTK_LIBRARY NAMES asmtk)
        find_path(ASMTK_INCLUDE_DIR NAMES asmtk/asmtk.h)
        target_link_libraries(${PROJECT_NAME} PUBLIC ${ASMTK_LIBRARY})
        target_include_directories(${PROJECT_NAME} PUBLIC ${ASMTK_INCLUDE_DIR})
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
		#target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/tests/${DYNOHOOK_OS}/test_${DYNOHOOK_BUILD_PREFIX}_detour.cpp
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
		#target_sources(${PROJECT_NAME} PRIVATE
		#	${PROJECT_SOURCE_DIR}/tests/${DYNOHOOK_OS}/test_vtable.cpp
		#	${PROJECT_SOURCE_DIR}/tests/${DYNOHOOK_OS}/test_vhook.cpp)
	endif()
endif()

#Feature/CallConv
if(DYNOHOOK_BUILD_64)
	set(DYNOHOOK_CALLCONV_HEADERS
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x64/x64MsFastcall.h
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x64/x64SystemVcall.h)
	install(FILES ${DYNOHOOK_CALLCONV_HEADERS} DESTINATION include/dynohook/conventions)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x64/x64MsFastcall.cpp
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x64/x64SystemVcall.cpp)
elseif(DYNOHOOK_BUILD_32)
	set(DYNOHOOK_CALLCONV_HEADERS
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86GccCdecl.h
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86GccThiscall.h
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsCdecl.h
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsFastcall.h
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsStdcall.h
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsThiscall.h)
	install(FILES ${DYNOHOOK_CALLCONV_HEADERS} DESTINATION include/dynohook/conventions)

	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsCdecl.cpp
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsFastcall.cpp
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsStdcall.cpp
		${PROJECT_SOURCE_DIR}/dynohook/conventions/x86/x86MsThiscall.cpp)
endif()

#Tests
if(NOT DYNOHOOK_BUILD_DLL)
	target_link_libraries(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:Catch2>)
    target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/catch2/src/catch2>)
	target_sources(${PROJECT_NAME} PRIVATE
		${PROJECT_SOURCE_DIR}/tests/main_tests.cpp
	    ${PROJECT_SOURCE_DIR}/tests/${DYNOHOOK_OS}/test_disassembler.cpp
	    ${PROJECT_SOURCE_DIR}/tests/${DYNOHOOK_OS}/test_detour_translation_x64.cpp
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