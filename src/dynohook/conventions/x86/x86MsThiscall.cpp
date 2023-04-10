#include "x86MsThiscall.hpp"

#ifdef ENV32BIT

using namespace dyno;

x86MsThiscall::x86MsThiscall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
    x86MsStdcall{std::move(arguments), returnType, alignment} {

    if (!m_arguments.empty()) {
        m_arguments[0].reg = ECX;
    }

    init();
}

x86MsThiscall::~x86MsThiscall() {
}

#endif // ENV32BIT