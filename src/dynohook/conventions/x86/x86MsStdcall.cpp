#include "x86MsStdcall.hpp"

#ifdef ENV32BIT

using namespace dyno;

x86MsStdcall::x86MsStdcall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
        x86MsCdecl{std::move(arguments), returnType, alignment} {
    init();
}

x86MsStdcall::~x86MsStdcall() {
}

size_t x86MsStdcall::getPopSize() {
    return m_iStackSize;
}

#endif