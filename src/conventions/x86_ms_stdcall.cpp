#include <dynohook/conventions/x86_ms_stdcall.h>

using namespace dyno;

x86MsStdcall::x86MsStdcall(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
        x86MsCdecl{std::move(arguments), returnType, alignment} {
    init();
}

size_t x86MsStdcall::getPopSize() {
    return m_stackSize;
}