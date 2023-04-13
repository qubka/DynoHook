#pragma once

#if DYNO_ARCH_X86 == 32

#include "dynohook/convention.hpp"
#include "x86MsCdecl.hpp"

namespace dyno {
    typedef x86MsCdecl x86GccThiscall;
}

#endif // DYNO_ARCH_X86