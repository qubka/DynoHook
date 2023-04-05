#pragma once

#ifdef ENV64BIT

#include "dynohook/convention.hpp"

namespace dyno {

    class x64MsStdcall : public ICallingConvention {
    public:
        x64MsStdcall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment = 8);
        ~x64MsStdcall() override;

        std::vector<RegisterType> getRegisters() override;

        void** getStackArgumentPtr(const Registers &registers) override;
        void* getArgumentPtr(size_t index, const Registers& registers) override;
        void* getReturnPtr(const Registers& registers) override;
    };
}

#endif