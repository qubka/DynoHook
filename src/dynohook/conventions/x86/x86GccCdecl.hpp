#pragma once

#ifndef DYNO_PLATFORM_X64

#include "x86MsCdecl.hpp"

namespace dyno {
    typedef x86MsCdecl x86GccCdecl;
}

#endif // DYNO_PLATFORM_X64