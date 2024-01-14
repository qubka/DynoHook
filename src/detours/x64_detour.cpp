#include <dynohook/detours/x64_detour.h>

#include <asmtk/asmtk.h>
#include <Zydis/Register.h>

using namespace std::string_literals;

using namespace dyno;
using namespace asmjit;

x64Detour::x64Detour(uintptr_t fnAddress, const ConvFunc& convention) :
    Detour(fnAddress, convention, getArchType()), m_allocator{8, 100} {
}

x64Detour::~x64Detour() {
    if (m_valloc2_region) {
        m_allocator.deallocate(*m_valloc2_region);
        m_valloc2_region = {};
    }
}

Mode x64Detour::getArchType() const {
    return Mode::x64;
}

uint8_t x64Detour::getMinJmpSize() {
    return 6;
}

x64Detour::detour_scheme_t x64Detour::getDetourScheme() const {
    return m_detourScheme;
}

void x64Detour::setDetourScheme(detour_scheme_t scheme) {
    m_detourScheme = scheme;
}

const char* x64Detour::printDetourScheme(detour_scheme_t scheme) {
    switch (scheme) {
        case VALLOC2: return "VALLOC2";
        case INPLACE: return "INPLACE";
        case CODE_CAVE: return "CODE_CAVE";
        case INPLACE_SHORT: return "INPLACE_SHORT";
        case RECOMMENDED: return "RECOMMENDED";
        case ALL: return "ALL";
        default: return "UNKNOWN";
    }
}

template<uint16_t SIZE>
std::optional<uintptr_t> x64Detour::findNearestCodeCave(uintptr_t address) {
    static_assert(SIZE + 1 < FINDPATTERN_SCRATCH_SIZE);
    static_assert(SIZE + 1 < FINDPATTERN_SCRATCH_SIZE);

    const size_t chunkSize = 64000;
    auto data = std::make_unique<uint8_t[]>(chunkSize);

    // RPM so we don't pagefault, careful to check for partial reads

    // these patterns are listed in order of most accurate to least accurate with size taken into account
    // simple c3 ret is more accurate than c2 ?? ?? and series of CC or 90 is more accurate than complex multi-byte nop

    constexpr String CC_PATTERN = repeat_n<SIZE>("cc ");
    constexpr String NOP_PATTERN = repeat_n<SIZE>("90 ");
    constexpr String CC_PATTERN_RET = concat("c3 ", CC_PATTERN.c);
    constexpr String NOP1_PATTERN_RET = concat("c3 ", NOP_PATTERN.c);
    constexpr String CC_PATTERN_RETN = concat("c2 ?? ?? ", CC_PATTERN.c);
    constexpr String NOP1_PATTERN_RETN = concat("c2 ?? ?? ", NOP_PATTERN.c);

    const char* NOP2_RET = "c3 0f 1f 44 00 00";
    const char* NOP3_RET = "c3 0f 1f 84 00 00 00 00 00";
    const char* NOP4_RET = "c3 66 0f 1f 84 00 00 00 00 00";
    const char* NOP5_RET = "c3 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP6_RET = "c3 cc cc cc cc cc cc 66 0f 1f 44 00 00";
    const char* NOP7_RET = "c3 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP8_RET = "c3 cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
    const char* NOP9_RET = "c3 cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP10_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP11_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";

    const char* NOP2_RETN = "c2 ?? ?? 0f 1f 44 00 00";
    const char* NOP3_RETN = "c2 ?? ?? 0f 1f 84 00 00 00 00 00";
    const char* NOP4_RETN = "c2 ?? ?? 66 0f 1f 84 00 00 00 00 00";
    const char* NOP5_RETN = "c2 ?? ?? 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP6_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 44 00 00";
    const char* NOP7_RETN = "c2 ?? ?? 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP8_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
    const char* NOP9_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP10_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
    const char* NOP11_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";

    // Scan in the same order as listing above
    const char* PATTERNS_OFF1[] = {
        CC_PATTERN_RET.c, NOP1_PATTERN_RET.c, NOP2_RET, NOP3_RET, NOP4_RET,
        NOP5_RET, NOP6_RET, NOP7_RET, NOP8_RET, NOP9_RET, NOP10_RET, NOP11_RET
    };

    const char* PATTERNS_OFF3[] = {
        CC_PATTERN_RETN.c, NOP1_PATTERN_RETN.c, NOP2_RETN, NOP3_RETN, NOP4_RETN,
        NOP5_RETN, NOP6_RETN, NOP7_RETN, NOP8_RETN, NOP9_RETN, NOP10_RETN, NOP11_RETN
    };

    // Most common:
    // https://gist.github.com/stevemk14ebr/d117e8d0fd1432fb2a92354a034ce5b9
    // We check for rets to verify it's not like a mid function or jmp table pad
    // [0xc3 | 0xC2 ? ? ? ? ] & 6666666666660f1f840000000000
    // [0xc3 | 0xC2 ? ? ? ? ] & 0f1f440000
    // [0xc3 | 0xC2 ? ? ? ? ] & 0f1f840000000000
    // [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f440000
    // [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f840000000000
    // [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccc66660f1f840000000000
    // [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccccccccccccccccc66660f1f840000000000
    // [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc66660f1f840000000000
    // [0xc3 | 0xC2 ? ? ? ? ] & 66660f1f840000000000
    // [0xc3 | 0xC2 ? ? ? ? ] & 660f1f840000000000

    // Search 2GB below
    for (uintptr_t search = address - chunkSize; (search + chunkSize) >= calc_2gb_below(address); search -= chunkSize) {
        size_t read = 0;
        if (safe_mem_read(search, (uintptr_t) data.get(), chunkSize, read)) {
            assert(read <= chunkSize);
            if (read == 0 || read < SIZE)
                continue;

            auto finder = [&](const char* pattern, uintptr_t offset) -> std::optional<uintptr_t> {
                if (auto found = findPattern_rev((uintptr_t) data.get(), read, pattern)) {
                    return search + (found + offset - (uintptr_t) data.get());
                }
                return std::nullopt;
            };

            for (const char* pat : PATTERNS_OFF1) {
                if (getPatternSize(pat) - 1 < SIZE)
                    continue;

                if (auto found = finder(pat, 1)) {
                    return found;
                }
            }

            for (const char* pat : PATTERNS_OFF3) {
                if (getPatternSize(pat) - 3 < SIZE)
                    continue;

                if (auto found = finder(pat, 3)) {
                    return found;
                }
            }
        }
    }

    // Search 2GB above
    for (uintptr_t search = address; (search + chunkSize) < calc_2gb_above(address); search += chunkSize) {
        size_t read = 0;
        if (safe_mem_read(search, (uintptr_t) data.get(), chunkSize, read)) {
//            uint32_t contiguousInt3 = 0;
//            uint32_t contiguousNop = 0;

            assert(read <= chunkSize);
            if (read == 0 || read < SIZE) {
                continue;
            }

            auto finder = [&](const char* pattern, uintptr_t offset) -> std::optional<uintptr_t> {
                if (auto found = findPattern((uintptr_t) data.get(), read, pattern)) {
                    return search + (found + offset - (uintptr_t) data.get());
                }
                return std::nullopt;
            };

            for (const char* pat : PATTERNS_OFF1) {
                if (getPatternSize(pat) - 1 < SIZE) {
                    continue;
                }

                if (auto found = finder(pat, 1)) {
                    return found;
                }
            }

            for (const char* pat : PATTERNS_OFF3) {
                if (getPatternSize(pat) - 3 < SIZE) {
                    continue;
                }

                if (auto found = finder(pat, 3)) {
                    return found;
                }
            }
        }
    }
    return std::nullopt;
}

bool x64Detour::makeInplaceTrampoline(
    uintptr_t base_address,
    const std::function<void(asmjit::x86::Assembler&)>& builder
) {
    CodeHolder code;
    code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpuFeatures(), base_address);
    x86::Assembler a(&code);

    builder(a);

    uintptr_t trampoline_address;
    auto error = m_asmjit_rt.add(&trampoline_address, &code);

    if (error) {
        DYNO_LOG("Failed to generate in-place trampoline: "s + asmjit::DebugUtils::errorAsString(error), ErrorLevel::SEV);
        return false;
    }

    const auto trampoline_end = trampoline_address + code.codeSize();
    m_hookInsts = m_disasm.disassemble(trampoline_address, trampoline_address, trampoline_end, *this);
    // Fix the addresses
    auto current_address = base_address;
    for (auto& inst: m_hookInsts) {
        inst.setAddress(current_address);
        current_address += inst.size();
    }
    return true;
}

bool x64Detour::allocateJumpToBridge() {
    // Create the bridge function
    if (!createBridge()) {
        DYNO_LOG("Failed to create bridge", ErrorLevel::SEV);
        return false;
    }

    // Insert valloc description
    if (m_detourScheme & detour_scheme_t::VALLOC2 && boundedAllocSupported()) {
        auto max = AlignDownwards(calc_2gb_above(m_fnAddress), getPageSize());
        auto min = AlignDownwards(calc_2gb_below(m_fnAddress), getPageSize());

        // each block is m_blocksize (8) at the time of writing. Do not write more than this.
        auto region = (uintptr_t) m_allocator.allocate(min, max);
        if (!region) {
            DYNO_LOG("VirtualAlloc2 failed to find a region near function", ErrorLevel::SEV);
        } else if (region < min || region >= max) {
            // Workaround for WINE bug, VirtualAlloc2 does not return region in the correct range (always?)
            // see: https://github.com/stevemk14ebr/PolyHook_2_0/pull/168
            m_allocator.deallocate(region);
            region = 0;
            DYNO_LOG("VirtualAlloc2 failed allocate within requested range", ErrorLevel::SEV);
            // intentionally try other schemes.
        } else {
            m_valloc2_region = region;

            MemProtector region_protector(region, 8, ProtFlag::RWX, *this, false);
            m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnBridge, region);
            m_chosenScheme = detour_scheme_t::VALLOC2;
            return true;
        }
    }

    // The In-place scheme may only be done for functions with a large enough prologue,
    // otherwise this will overwrite adjacent bytes. The default in-place scheme is non-spoiling,
    // but larger, which reduces chances of success.
    if (m_detourScheme & detour_scheme_t::INPLACE) {
        const auto success = makeInplaceTrampoline(m_fnAddress, [&](auto &a) {
            a.lea(x86::rsp, x86::ptr(x86::rsp, -0x80));
            a.push(x86::rax);
            a.mov(x86::rax, m_fnBridge);
            a.xchg(x86::ptr(x86::rsp), x86::rax);
            a.ret(0x80);
        });

        if (success) {
            m_chosenScheme = detour_scheme_t::INPLACE;
            return true;
        }
    }

    // Code cave is our last recommended approach since it may potentially find a region of unstable memory.
    // We're really space constrained, try to do some stupid hacks like checking for 0xCC's near us
    if (m_detourScheme & detour_scheme_t::CODE_CAVE) {
        auto cave = findNearestCodeCave<8>(m_fnAddress);
        if (cave) {
            MemProtector cave_protector(*cave, 8, ProtFlag::RWX, *this, false);
            m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnBridge, *cave);
            m_chosenScheme = detour_scheme_t::CODE_CAVE;
            return true;
        }

        DYNO_LOG("No code caves found near function", ErrorLevel::SEV);
    }

    // This short in-place scheme works almost like the default in-place scheme, except that it doesn't
    // try to not spoil shadow space. It doesn't mean that it will necessarily spoil it, though.
    if (m_detourScheme & detour_scheme_t::INPLACE_SHORT) {
        const auto success = makeInplaceTrampoline(m_fnAddress, [&](auto &a) {
            a.mov(x86::rax, m_fnBridge);
            a.push(x86::rax);
            a.ret();
        });

        if (success) {
            m_chosenScheme = detour_scheme_t::INPLACE_SHORT;
            return true;
        }
    }

    DYNO_LOG("None of the allowed hooking schemes have succeeded", ErrorLevel::SEV);

    if (m_hookInsts.empty()) {
        DYNO_LOG("Invalid state: hook instructions are empty", ErrorLevel::SEV);
    }

    return false;
}

bool x64Detour::hook() {
    DYNO_LOG("m_fnAddress: " + int_to_hex(m_fnAddress) + "\n", ErrorLevel::INFO);

    insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
    DYNO_LOG("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

    if (insts.empty()) {
        DYNO_LOG("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
        return false;
    }

    if (!followJmp(insts)) {
        DYNO_LOG("Prologue jmp resolution failed", ErrorLevel::SEV);
        return false;
    }

    // update given fn address to resolved one
    m_fnAddress = insts.front().getAddress();

    if (!allocateJumpToBridge()) {
        return false;
    }

    {
        std::stringstream ss;
        ss << printDetourScheme(m_chosenScheme);
        DYNO_LOG("Chosen detour scheme: " + ss.str() + "\n", ErrorLevel::INFO);
    }

    // min size of patches that may split instructions
    // For valloc & code cave, we insert the jump, hence we take only size of the 1st instruction.
    // For detours, we calculate the size of the generated code.
    uintptr_t minProlSz = (m_chosenScheme == VALLOC2 || m_chosenScheme == CODE_CAVE) ? m_hookInsts.begin()->size() :
                         m_hookInsts.rbegin()->getAddress() + m_hookInsts.rbegin()->size() -
                         m_hookInsts.begin()->getAddress();

    uintptr_t roundProlSz = minProlSz;  // nearest size to min that doesn't split any instructions

    // find the prologue section we will overwrite with jmp + zero or more nops
    auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
    if (!prologueOpt) {
        DYNO_LOG("Function too small to hook safely!", ErrorLevel::SEV);
        return false;
    }

    assert(roundProlSz >= minProlSz);
    auto prologue = *prologueOpt;

    if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
        DYNO_LOG("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
        return false;
    }

    m_originalInsts = prologue;

    DYNO_LOG("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);

    // copy all the prologue stuff to trampoline
    insts_t jmpTblOpt;
    if (!makeTrampoline(prologue, jmpTblOpt)) {
        return false;
    }

    DYNO_LOG("m_trampoline: " + int_to_hex(m_trampoline) + "\n", ErrorLevel::INFO);
    DYNO_LOG("m_trampolineSz: " + int_to_hex(m_trampolineSz) + "\n", ErrorLevel::INFO);

    auto tramp_instructions = m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this);
    DYNO_LOG("Trampoline:\n" + instsToStr(tramp_instructions) + "\n", ErrorLevel::INFO);
    if (!jmpTblOpt.empty()) {
        DYNO_LOG("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n", ErrorLevel::INFO);
    }

    m_hookSize = (uint32_t) roundProlSz;
    m_nopProlOffset = (uint16_t) minProlSz;

    DYNO_LOG("Hook instructions: \n" + instsToStr(m_hookInsts) + "\n", ErrorLevel::INFO);
    MemProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);
    writeEncoding(m_hookInsts);

    DYNO_LOG("Hook size: " + std::to_string(m_hookSize) + "\n", ErrorLevel::INFO);
    DYNO_LOG("Prologue offset: " + std::to_string(m_nopProlOffset) + "\n", ErrorLevel::INFO);

    // Nop the space between jmp and end of prologue
    assert(m_hookSize >= m_nopProlOffset);
    m_nopSize = (uint16_t) (m_hookSize - m_nopProlOffset);
    const auto nops = make_nops(m_fnAddress + m_nopProlOffset, m_nopSize);
    writeEncoding(nops);

    m_hooked = true;
    return true;
}

bool x64Detour::unhook() {
    bool status = Detour::unhook();
    if (m_valloc2_region) {
        m_allocator.deallocate(*m_valloc2_region);
        m_valloc2_region = {};
    }
    return status;
}

/**
 * Holds a list of instructions that require us to store contents of the scratch register
 * into the original destination address. For example, in `add [0x...], rbx` after translation
 * we also need to store it: `add rax, rbx` && `mov [r15], rax`, where as in cmp instruction for
 * instance there is no such requirement.
 */
const static std::set<std::string> instructions_to_store{ // NOLINT(cert-err58-cpp)
    "adc", "add", "and", "bsf", "bsr", "btc", "btr", "bts",
    "cmovb", "cmove", "cmovl", "cmovle", "cmovnb", "cmovnbe", "cmovnl", "cmovnle",
    "cmovno", "cmovnp", "cmovns", "cmovnz", "cmovo", "cmovp", "cmovs", "cmovz",
    "cmpxchg", "crc32", "cvtsi2sd", "cvtsi2ss", "dec", "extractps", "inc", "mov",
    "neg", "not", "or", "pextrb", "pextrd", "pextrq", "rcl", "rcr", "rol", "ror",
    "sal", "sar", "sbb", "setb", "setbe", "setl", "setle", "setnb", "setnbe", "setnl",
    "setnle", "setno", "setnp", "setns", "setnz", "seto", "setp", "sets", "setz", "shl",
    "shld", "shr", "shrd", "sub", "verr", "verw", "xadd", "xchg", "xor"
};

const static std::map<ZydisRegister, ZydisRegister> a_to_b{ // NOLINT(cert-err58-cpp)
    {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX},
    {ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_EBX},
    {ZYDIS_REGISTER_AX,  ZYDIS_REGISTER_BX},
    {ZYDIS_REGISTER_AH,  ZYDIS_REGISTER_BH},
    {ZYDIS_REGISTER_AL,  ZYDIS_REGISTER_BL},
};

const static std::map<ZydisRegisterClass, ZydisRegister> class_to_reg{ // NOLINT(cert-err58-cpp)
    {ZYDIS_REGCLASS_GPR64, ZYDIS_REGISTER_RAX},
    {ZYDIS_REGCLASS_GPR32, ZYDIS_REGISTER_EAX},
    {ZYDIS_REGCLASS_GPR16, ZYDIS_REGISTER_AX},
    {ZYDIS_REGCLASS_GPR8,  ZYDIS_REGISTER_AL},
};

/**
 * For push/pop operations, we have to use 64-bit operands.
 * This map translates all possible scratch registers into
 * the corresponding 64-bit register for push/pop operations.
 */
const static std::map<std::string, std::string> scratch_to_64{ // NOLINT(cert-err58-cpp)
    {"rbx", "rbx"},
    {"ebx", "rbx"},
    {"bx",  "rbx"},
    {"bh",  "rbx"},
    {"bl",  "rbx"},
    {"rax", "rax"},
    {"eax", "rax"},
    {"ax",  "rax"},
    {"ah",  "rax"},
    {"al",  "rax"},
};

struct TranslationResult {
    std::string instruction;
    std::string scratch_register;
    std::string address_register;
};

/**
 * Generates an equivalent instruction that replaces memory operand with register
 * of corresponding size.
 */
std::optional<TranslationResult> translateInstruction(const Instruction& instruction) {
    const auto& mnemonic = instruction.getMnemonic();
    ZydisRegister scratch_register;
    std::string scratch_register_string, address_register_string, second_operand_string;

    if (instruction.hasImmediate()) {// 2nd operand is immediate
        const auto inst_contains = [&](const std::string& needle) {
            return instruction.getFullName().find(needle) != std::string::npos;
        };

        // We need to pick a register that matches the pointer size.
        // Only the mov instruction can encode 64-bit immediate, so it is a special case
        scratch_register_string =
            inst_contains("qword") ? (instruction.getMnemonic() == "mov" ? "rax" : "eax") :
            inst_contains("dword") ? "eax" :
            inst_contains("word") ? "ax" :
            inst_contains("byte") ? "al" : "";

        if (scratch_register_string.empty()) {
            DYNO_LOG("Failed to detect pointer size: " + instruction.getFullName(), ErrorLevel::SEV);
            return std::nullopt;
        }

        const auto imm_size = instruction.getImmediateSize();
        const auto immediate_string =
            imm_size == 8 ? int_to_hex((uint64_t) instruction.getImmediate()) :
            imm_size == 4 ? int_to_hex((uint32_t) instruction.getImmediate()) :
            imm_size == 2 ? int_to_hex((uint16_t) instruction.getImmediate()) :
            imm_size == 1 ? int_to_hex((uint8_t) instruction.getImmediate()) : "";

        if (immediate_string.empty()) {
            DYNO_LOG("Unexpected size of immediate: " + std::to_string(imm_size), ErrorLevel::SEV);
            return std::nullopt;
        }

        address_register_string = "r15";
        second_operand_string = immediate_string;
    } else if (instruction.hasRegister()) {// 2nd operand is register
        const auto reg = (ZydisRegister) instruction.getRegister();
        const auto regClass = ZydisRegisterGetClass(reg);
        const std::string reg_string = ZydisRegisterGetString(reg);

        if (a_to_b.count(reg)) {
            // This is a register A
            scratch_register = a_to_b.at(reg);
        } else if (class_to_reg.count(regClass)) {
            // This is not a register A
            scratch_register = class_to_reg.at(regClass);
        } else {
            // Unexpected register
            DYNO_LOG("Unexpected register: " + reg_string, ErrorLevel::SEV);
            return std::nullopt;
        }

        scratch_register_string = ZydisRegisterGetString(scratch_register);

        if (!scratch_to_64.count(scratch_register_string)) {
            DYNO_LOG("Unexpected scratch register: " + scratch_register_string, ErrorLevel::SEV);
            return std::nullopt;
        }

        address_register_string = reg_string.find("r15") != std::string::npos ? "r14" : "r15";
        second_operand_string = reg_string;
    } else {
        DYNO_LOG("No translation support for such instruction", ErrorLevel::SEV);
        return std::nullopt;
    }

    const auto& operand1 = instruction.startsWithDisplacement() ? scratch_register_string : second_operand_string;
    const auto& operand2 = instruction.startsWithDisplacement() ? second_operand_string : scratch_register_string;

    TranslationResult result;
    result.instruction = mnemonic + " " + operand1 + ", " + operand2;
    result.scratch_register = std::move(scratch_register_string);
    result.address_register = std::move(address_register_string);

    return { result };
}

/**
 * Generates a jump with full 64-bit absolute address without spoiling any registers
 */
std::vector<std::string> generateAbsoluteJump(uintptr_t destination, uint16_t stack_clean_size) {
    std::vector<std::string> instructions;
    instructions.reserve(4);

    // Save rax
    instructions.emplace_back("push rax");

    // Load destination into rax
    instructions.emplace_back("mov rax, " + int_to_hex(destination));

    // Restore rax and set up the return address
    instructions.emplace_back("xchg [rsp], rax");

    // Finally, make the jump
    instructions.emplace_back("ret " + int_to_hex(stack_clean_size));

    return instructions;
}

/**
 * @returns address of the first instructions of the translation routine
 */
std::optional<uintptr_t> x64Detour::generateTranslationRoutine(const Instruction& instruction, uintptr_t resume_address) {
    // AsmTK parses strings for AsmJit, which generates the binary code.
    CodeHolder code;
    code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpuFeatures());

    x86::Assembler assembler(&code);
    asmtk::AsmParser parser(&assembler);

    // Stores vector of instruction strings that comprise translation routine
    std::vector<std::string> translation;

    // LEA is special case, it doesn't need dereferenced like the sequences below always generate
    // TODO: handle LEA's that do actual math, we assume the LEA is always constant right now

    // ALWAYS: Avoid spoiling the shadow space
    translation.emplace_back("lea rsp, [rsp - 0x80]");
    if (instruction.getMnemonic() == "lea") { // lea rax, ds:[0x00007FFD4FFDC400]
        uint64_t relativeDest = instruction.getRelativeDestination();
        const std::string reg_string = ZydisRegisterGetString((ZydisRegister) instruction.getRegister());

        // translate the relative LEA into a fixed MOV, using same register and it's computed relative address
        translation.emplace_back("mov " + reg_string + ", " + int_to_hex(relativeDest));
    } else {
        const auto result = translateInstruction(instruction);
        if (!result) {
            return std::nullopt;
        }

        const auto& [translated_instruction, scratch_register, address_register] = *result;

        const auto& scratch_register_64 = scratch_to_64.at(scratch_register);

        // Save the scratch register
        translation.emplace_back("push " + scratch_register_64);

        // Save the address holder register
        translation.emplace_back("push " + address_register);

        // Load the destination address into the address holder register
        const auto destination = int_to_hex(instruction.getDestination());
        translation.emplace_back("mov " + address_register + ", " + destination);

        // Load the destination content into scratch register
        translation.emplace_back("mov " + scratch_register + ", [" + address_register + "]");

        // Replace RIP-relative instruction
        translation.emplace_back(translated_instruction);

        // Store the scratch register content into the destination, if necessary
        if (instruction.startsWithDisplacement() && instructions_to_store.count(instruction.getMnemonic())) {
            translation.emplace_back("mov [" + address_register + "], " + scratch_register_64);
        }

        // Restore the memory holder register
        translation.emplace_back("pop " + address_register);

        // Restore the scratch register
        translation.emplace_back("pop " + scratch_register_64);
    }

    // ALWAYS: Jump back to trampoline, ret cleans up the lea from earlier
    // we do it this way to ensure pushing our return address doesn't overwrite shadow space
    const auto jump_instructions = generateAbsoluteJump(resume_address, 0x80);
    translation.insert(translation.end(), jump_instructions.begin(), jump_instructions.end());

    // Join all instructions into one string delimited by newlines
    std::ostringstream translation_stream;
    std::copy(translation.begin(), translation.end(), std::ostream_iterator<std::string>(translation_stream, "\n"));
    const auto translation_string = translation_stream.str();

    DYNO_LOG("Translation:\n" + translation_string + "\n", ErrorLevel::INFO);

    // Parse the instructions via AsmTK
    if (auto error = parser.parse(translation_string.c_str())) {
        DYNO_LOG("AsmTK error: "s + DebugUtils::errorAsString(error), ErrorLevel::SEV);
        return std::nullopt;
    }

    // Generate the binary code via AsmJit
    uintptr_t translation_address = 0;
    if (auto error = m_asmjit_rt.add(&translation_address, &code)) {
        DYNO_LOG("AsmJit error: "s + DebugUtils::errorAsString(error), ErrorLevel::SEV);
        return std::nullopt;
    }

    DYNO_LOG("Translation address: " + int_to_hex(translation_address) + "\n", ErrorLevel::INFO);

    return { translation_address };
}

/**
 * Makes an instruction with stored absolute address, but sets the instruction as relative
 * to fit into the existing entry-table logic
 */
Instruction x64Detour::makeRelJmpWithAbsDest(uintptr_t address, uintptr_t abs_destination) {
    Instruction::Displacement disp{0};
    disp.Absolute = abs_destination;
    Instruction instruction(
        this, address, disp, 1, true, false, { 0xE9, 0, 0, 0, 0 }, "jmp", int_to_hex(abs_destination), Mode::x64
	);
    instruction.setDisplacementSize(4);
    instruction.setHasDisplacement(true);

    return instruction;
}

bool x64Detour::makeTrampoline(insts_t& prologue, insts_t& outJmpTable) {
    assert(!prologue.empty());
    assert(m_trampoline == 0);

    const uintptr_t prolStart = prologue.front().getAddress();
    const uint16_t prolSz = calcInstsSz(prologue);
    const uint8_t destHldrSz = 8;

    /**
     * Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
     * address will change each attempt, which changes delta, which changes the number of needed entries. So
     * we just try until we hit that lucky number that works
     *
     * The relocation could also because of data operations too. But that's specific to the function and can't
     * work again on a retry (same function, duh). Return immediately in that case.
     */
    insts_t instsNeedingEntry;
    insts_t instsNeedingReloc;
    insts_t instsNeedingTranslation;
    insts_t instsNeedingAbsJmps;
    intptr_t delta;

    uint8_t neededEntryCount = std::max((uint8_t) instsNeedingEntry.size(), (uint8_t) 5);

    const auto jmp_size = getMinJmpSize() + destHldrSz; // 14
    const auto alignment_pad_size = 7; //extra bytes for dest-holders 8 bytes alignment

    // prol + jmp back to prol + N * jmpEntries + align pad
    m_trampolineSz = (uint16_t) (prolSz + jmp_size * (1 + neededEntryCount) + alignment_pad_size);

    // allocate new trampoline before deleting old to increase odds of new mem address
    auto tmpTrampoline = (uintptr_t) new uint8_t[m_trampolineSz];
    if (m_trampoline != 0) {
        delete[] (uint8_t*) m_trampoline;
    }

    m_trampoline = tmpTrampoline;
    delta = (intptr_t) (m_trampoline - prolStart);

    buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc, instsNeedingTranslation);
    if (!instsNeedingEntry.empty()) {
        DYNO_LOG("Instructions needing entry:\n" + instsToStr(instsNeedingEntry) + "\n", ErrorLevel::INFO);
    }
    if (!instsNeedingReloc.empty()) {
        DYNO_LOG("Instructions needing relocation:\n" + instsToStr(instsNeedingReloc) + "\n", ErrorLevel::INFO);
    }
    if (!instsNeedingTranslation.empty()) {
        DYNO_LOG("Instructions needing translation:\n" + instsToStr(instsNeedingTranslation) + "\n", ErrorLevel::INFO);
    }

    DYNO_LOG("Trampoline address: " + int_to_hex(m_trampoline), ErrorLevel::INFO);

    for (auto& instruction: instsNeedingTranslation) {
        const auto inst_offset = instruction.getAddress() - prolStart;
        // Address of the instruction that follows the problematic instruction
        const uintptr_t resume_address = m_trampoline + inst_offset + instruction.size();
        auto opt_translation_address = generateTranslationRoutine(instruction, resume_address);
        if (!opt_translation_address)
            return false;

        // replace the rip-relative instruction with jump to translation
        auto inst_iterator = std::find(prologue.begin(), prologue.end(), instruction);
        const auto jump = makeRelJmpWithAbsDest(instruction.getAddress(), *opt_translation_address);
        *inst_iterator = jump;
        instsNeedingEntry.push_back(jump);
        instsNeedingAbsJmps.push_back(jump);

        // nop the garbage bytes if necessary.
        const auto nop_size = (uint16_t) (instruction.size() - jump.size());
        if (nop_size < 1) {
            continue;
        }

        const auto nop_base = jump.getAddress() + jump.size();
        for (auto&& nop : make_nops(nop_base, nop_size)) {
            if (inst_iterator == prologue.end()) {
                prologue.push_back(nop);
                inst_iterator = prologue.end();
            } else {
                // insert after current instruction
                inst_iterator = prologue.insert(inst_iterator + 1, nop);
            }
        }
    }

    MemProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

    // Insert jmp from trampoline -> prologue after overwritten section
    const uintptr_t jmpToProlAddr = m_trampoline + prolSz;

    const auto trampoline_end = m_trampoline + m_trampolineSz;
    // & ~0x7 for 8 bytes align for performance.
    const uintptr_t jmpHolderCurAddr = (trampoline_end - destHldrSz) & ~0x7;
    const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prolStart + prolSz, jmpHolderCurAddr);

    DYNO_LOG("Jmp To Prol:\n" + instsToStr(jmpToProl) + "\n", ErrorLevel::INFO);
    writeEncoding(jmpToProl);

    // each jmp tbl entries holder is one slot down from the previous (lambda holds state)
    const auto makeJmpFn = [&, captureAddress = jmpHolderCurAddr](uintptr_t a, Instruction& inst) mutable {
        captureAddress -= destHldrSz;
        assert(captureAddress > (uintptr_t) m_trampoline && (captureAddress + destHldrSz) < trampoline_end);

        // move inst to trampoline and point instruction to entry
        const bool isIndirectCall = inst.isCalling() && inst.isIndirect();
        const bool isAbsJmp = std::find(instsNeedingAbsJmps.begin(), instsNeedingAbsJmps.end(), inst) != instsNeedingAbsJmps.end();
        auto oldDest = isAbsJmp ? inst.getAbsoluteDestination() : inst.getDestination();
        inst.setAddress(inst.getAddress() + delta);
        inst.setDestination(isIndirectCall ? captureAddress : a);

        // ff 25 indirect call re-written to point at dest-holder.
        // e8 direct call, or jmps of any kind point to literal jmp instruction
        return isIndirectCall
               ? makex64DestHolder(oldDest, captureAddress)
               : makex64MinimumJump(a, oldDest, captureAddress);
    };

    const uintptr_t jmpTblStart = jmpToProlAddr + getMinJmpSize();
    outJmpTable = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc, instsNeedingEntry);

    return true;
}