#pragma once

#include "registers.h"
#include "convention.h"
#include "mem_accessor.h"

#include <asmjit/asmjit.h>

namespace dyno {
    enum class HookMode : uint8_t {
        UNKNOWN,
        Detour,
        VEHHOOK,
        VTableSwap,
        IAT,
        EAT
    };

    enum class CallbackType : bool {
        Pre,  // callback will be executed before the original function
        Post  // callback will be executed after the original function
    };

    enum class ReturnAction : uint8_t {
        Ignored,  // handler didn't take any action
        Handled,  // we did something, but real function should still be called
        Override, // call real function, but use my return value
        Supercede // skip real function; use my return value
    };

    class Hook;
    typedef ReturnAction (*CallbackHandler)(CallbackType, Hook&);
    using ConvFunc = std::function<CallingConvention*()>;

    typedef std::unordered_map<uintptr_t, insts_t> branch_map_t;

    /**
	 * @brief Creates and manages hooks at the beginning of a function.
	 *
	 * This hooking method requires knowledge of parameters and calling convention of the target function.
	 */
    class Hook : public MemAccessor {
    public:
        /**
         * @brief Creates a new function hook.
         * @param func The address of the function to hook.
         * @param convention The calling convention of <func>.
         */
        explicit Hook(const ConvFunc& convention);
        ~Hook() override = default;
        DYNO_NONCOPYABLE(Hook);

        /**
         * @brief Adds a callback handler to the hook.
         * @param type The callback type.
         * @param handler The callback handler that should be added.
         */
        void addCallback(CallbackType type, CallbackHandler* handler);

        /**
         * @brief Removes a callback handler to the hook.
         * @param type The callback type.
         * @param handler The callback handler that should be removed.
         */
        void removeCallback(CallbackType type, CallbackHandler* handler);

        /**
         * @brief Checks if a callback handler is already added.
         * @param type The callback type.
         * @param handler The callback handler that should be checked.
         * @return
         */
        bool isCallbackRegistered(CallbackType type, CallbackHandler* handler) const;

        /**
         * @brief Checks if there are any callback handlers added to this hook.
         * @return
         */
        bool areCallbacksRegistered() const;

        template<class T>
        T getArgument(size_t index) const {
            return *(T*) m_callingConvention->getArgumentPtr(index, m_registers);
        }

        template<class T>
        void setArgument(size_t index, T value) {
            void* argumentPtr = m_callingConvention->getArgumentPtr(index, m_registers);
            *(T*) argumentPtr = value;
            m_callingConvention->onArgumentPtrChanged(index, m_registers, argumentPtr);
        }

        template<class T>
        T getReturnValue() const {
            return *(T*) m_callingConvention->getReturnPtr(m_registers);
        }

        template<class T>
        void setReturnValue(T value) {
            void* returnPtr = m_callingConvention->getReturnPtr(m_registers);
            *(T*) returnPtr = value;
            m_callingConvention->onReturnPtrChanged(m_registers, returnPtr);
        }

        ////

        virtual bool hook() = 0;
        virtual bool unhook() = 0;
        virtual bool rehook() {
            return true;
        }

        virtual uintptr_t getAddress() const = 0;

        virtual bool setHooked(bool state) {
            if (m_hooked == state)
                return true;

            return state ? hook() : unhook();
        }

        virtual bool isHooked() {
            return m_hooked;
        }

        virtual HookMode getMode() const = 0;

        ////

    protected:
        bool createBridge();
        bool createPostCallback();

    private:
        typedef asmjit::x86::Assembler Assembler;

        void writeModifyReturnAddress(Assembler& a);
        void writeCallHandler(Assembler& a, CallbackType type) const;
        void writeSaveRegisters(Assembler& a, CallbackType type) const;
        void writeRestoreRegisters(Assembler& a, CallbackType type) const;
        void writeSaveScratchRegisters(Assembler& a) const;
        void writeRestoreScratchRegisters(Assembler& a) const;
        void writeRegToMem(Assembler& a, const Register& reg, CallbackType type = CallbackType::Pre) const;
        void writeMemToReg(Assembler& a, const Register& reg, CallbackType type = CallbackType::Pre) const;

DYNO_OPTS_OFF
        DYNO_NOINLINE ReturnAction DYNO_CDECL hookHandler(CallbackType type);
        DYNO_NOINLINE void* DYNO_CDECL getReturnAddress(void* stackPtr);
        DYNO_NOINLINE void DYNO_CDECL setReturnAddress(void* retAddr, void* stackPtr);
DYNO_OPTS_ON

    protected:
        asmjit::JitRuntime m_asmjit_rt;

        // address of the bridge
        uintptr_t m_fnBridge;

        // address of new return
        uintptr_t m_newRetAddr;

        // interface if the calling convention
        std::unique_ptr<CallingConvention> m_callingConvention;

        // register storage
        Registers m_registers;
        Registers m_scratchRegisters;

        // save the last return action of the pre HookHandler for use in the post handler.
        std::vector<ReturnAction> m_lastPreReturnAction;

        // individual return's stack for stack pointers
        std::map<void*, std::vector<void*>> m_retAddr;

        // callbacks list
        std::map<CallbackType, std::vector<CallbackHandler*>> m_handlers;

        //
        bool m_hooked{ false };
    };
}