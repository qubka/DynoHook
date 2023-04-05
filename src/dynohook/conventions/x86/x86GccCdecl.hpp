#pragma once

#ifdef ENV32BIT

#include "x86MsCdecl.hpp"

namespace dyno {
    typedef x86MsCdecl x86GccCdecl;
}

#endif