#pragma once

#ifdef ENV32BIT

#include "dynohook/convention.hpp"
#include "x86MsCdecl.hpp"

namespace dyno {
    typedef x86MsCdecl x86GccThiscall;
}

#endif