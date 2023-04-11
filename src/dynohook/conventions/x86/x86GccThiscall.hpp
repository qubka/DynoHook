#pragma once

#ifndef DYNO_PLATFORM_X64

#include "dynohook/convention.hpp"
#include "x86MsCdecl.hpp"

namespace dyno {
    typedef x86MsCdecl x86GccThiscall;
}

#endif // DYNO_PLATFORM_X64