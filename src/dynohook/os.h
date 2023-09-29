// This file is used to not include os specific functions that might break other projects
// You should use it in sources

#if DYNO_PLATFORM_WINDOWS

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
  #define NOMINMAX
#endif
#include <windows.h>

#elif DYNO_PLATFORM_LINUX

#include <sys/mman.h>
#include <unistd.h>

#elif DYNO_PLATFORM_APPLE

#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_map.h>

#else

#error "Platform is not supported!"

#endif