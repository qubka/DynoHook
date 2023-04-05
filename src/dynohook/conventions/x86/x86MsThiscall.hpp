#pragma once

#ifdef ENV32BIT

#include "dynohook/convention.hpp"

/*
    Source: DynCall manual and Windows docs

    Registers:
        - eax = return value
        - ecx = this pointer
        - edx = return value
        - esp = stack pointer
        - st0 = floating point return value

    Parameter passing:
        - stack parameter order: right-to-left
        - callee cleans up the stack
        - all other arguments are pushed onto the stack
        - alignment: 4 bytes

    Return values:
        - return values of pointer or intergral type (<= 32 bits) are returned via the eax register
        - integers > 32 bits are returned via the eax and edx registers
        - floating pointer types are returned via the st0 register
*/
namespace dyno {
    class x86MsThiscall : public ICallingConvention {
    public:
        x86MsThiscall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment = 4);
        ~x86MsThiscall() override;

        std::vector<RegisterType> getRegisters() override;
        void** getStackArgumentPtr(const Registers& registers) override;

        void* getArgumentPtr(size_t index, const Registers& registers) override;
        void argumentPtrChanged(size_t index, const Registers& registers, void* argumentPtr) override;

        void* getReturnPtr(const Registers& registers) override;
        void returnPtrChanged(const Registers& registers, void* returnPtr) override;

    private:
        void* m_pReturnBuffer;
    };
}

#endif