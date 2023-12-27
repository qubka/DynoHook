#include <dynohook/conventions/x86_ms_thiscall.h>

using namespace dyno;

x86MsThiscall::x86MsThiscall(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
        x86MsStdcall{std::move(arguments), returnType, alignment} {

    if (!m_arguments.empty()) {
        m_arguments[0].reg = ECX;
    }

    init();
}