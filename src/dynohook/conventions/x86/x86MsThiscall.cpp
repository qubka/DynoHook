#include "x86MsThiscall.hpp"

#ifndef DYNO_PLATFORM_X64

using namespace dyno;

x86MsThiscall::x86MsThiscall(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
        x86MsStdcall(std::move(arguments), returnType, alignment) {

    if (!m_arguments.empty()) {
        m_arguments[0].reg = ECX;
    }

    init();
}

#endif // DYNO_PLATFORM_X64