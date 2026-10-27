#include "fathom/engine.hpp"
#include "fathom/util.hpp"

#include <capstone/capstone.h>

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace fathom {
namespace {

struct Engine {
    csh handle = 0;
    bool open = false;
    ~Engine() {
        if (open) {
            cs_close(&handle);
        }
    }
    Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
};

bool in_exec(const Program& program, uint64_t address) {
    const Section* section = section_containing(program, address);
    return section != nullptr && section->executable && !section->bytes.empty();
}

const Section* exec_section(const Program& program, uint64_t address) {
    const Section* section = section_containing(program, address);
    if (section == nullptr || !section->executable || section->bytes.empty()) {
        return nullptr;
    }
    if (address < section->va || address - section->va >= section->bytes.size()) {
        return nullptr;
    }
    return section;
}

std::optional<uint64_t> parse_hex_token(std::string_view text) {
    const auto pos = text.rfind("0x");
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    return parse_address(text.substr(pos));
}

Flow classify(csh handle, const cs_insn& insn) {
    if (cs_insn_group(handle, &insn, CS_GRP_RET) || cs_insn_group(handle, &insn, CS_GRP_IRET)) {
        return Flow::Return;
    }
    if (cs_insn_group(handle, &insn, CS_GRP_CALL)) {
        return Flow::Call;
    }
    if (cs_insn_group(handle, &insn, CS_GRP_INT)) {
        return Flow::Interrupt;
    }
    if (cs_insn_group(handle, &insn, CS_GRP_JUMP)) {
        const std::string_view mnemonic(insn.mnemonic);
        if (mnemonic == "jmp" || mnemonic == "b" || mnemonic == "br") {
            return Flow::Jump;
        }
        return Flow::CondJump;
    }
    return Flow::Fallthrough;
}

bool is_prologue(Arch arch, const Instruction& insn) {
    if (arch == Arch::X64 || arch == Arch::X86) {
        if (insn.mnemonic == "endbr64" || insn.mnemonic == "endbr32") {
            return true;
        }
        if (insn.mnemonic == "push" && (insn.op_str == "rbp" || insn.op_str == "ebp")) {
            return true;
        }
        if (insn.mnemonic == "sub" && (insn.op_str.starts_with("rsp") || insn.op_str.starts_with("esp"))) {
            return true;
        }
    }
    if (arch == Arch::Arm64) {
        if (insn.mnemonic == "pacibsp" || insn.mnemonic == "paciasp") {
            return true;
        }
        if (insn.mnemonic == "stp" && insn.op_str.find("x29") != std::string::npos &&
            insn.op_str.find("x30") != std::string::npos) {
            return true;
        }
    }
    return false;
}

struct Session {
    const Program* program = nullptr;
    Engine* engine = nullptr;
    std::map<uint64_t, Instruction> insns;
    std::deque<uint64_t> work;
    std::unordered_set<uint64_t> queued;
    std::set<uint64_t> entries;
    uint64_t cap = 0;
    bool truncated = false;
};

std::optional<Instruction> decode_at(Session& session, uint64_t address) {
    const Section* section = exec_section(*session.program, address);
    if (section == nullptr) {
        return std::nullopt;
    }
    const uint64_t offset = address - section->va;
    const uint8_t* code = section->bytes.data() + offset;
    size_t size = section->bytes.size() - static_cast<size_t>(offset);
    uint64_t cursor = address;
    cs_insn* insn = cs_malloc(session.engine->handle);
    if (insn == nullptr) {
        return std::nullopt;
    }
    const bool ok = cs_disasm_iter(session.engine->handle, &code, &size, &cursor, insn);
    std::optional<Instruction> out;
    if (ok && insn->size > 0 && insn->address == address) {
        Instruction item;
        item.address = insn->address;
        item.size = insn->size;
        item.mnemonic = insn->mnemonic;
        item.op_str = insn->op_str;
        item.bytes.assign(insn->bytes, insn->bytes + insn->size);
        item.flow = classify(session.engine->handle, *insn);
        if (insn->detail != nullptr &&
            (session.program->arch == Arch::X86 || session.program->arch == Arch::X64)) {
            const cs_x86& x86 = insn->detail->x86;
            const unsigned count = std::min<unsigned>(x86.op_count, 8);
            const bool branch = item.flow == Flow::Jump || item.flow == Flow::CondJump || item.flow == Flow::Call;
            for (unsigned i = 0; i < count; ++i) {
                const cs_x86_op& op = x86.operands[i];
                if (branch && !item.target && op.type == X86_OP_IMM) {
                    item.target = static_cast<uint64_t>(op.imm);
                }
                if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP && op.mem.index == X86_REG_INVALID) {
                    const uint64_t next = insn->address + insn->size;
                    if (op.mem.disp >= 0 || next >= static_cast<uint64_t>(-op.mem.disp)) {
                        item.mem_refs.push_back(static_cast<uint64_t>(static_cast<int64_t>(next) + op.mem.disp));
                    }
                }
            }
        } else if (insn->detail != nullptr && session.program->arch == Arch::Arm64) {
            const bool branch = item.flow == Flow::Jump || item.flow == Flow::CondJump || item.flow == Flow::Call;
            const unsigned count = std::min<unsigned>(insn->detail->arm64.op_count, 8);
            for (unsigned i = 0; i < count; ++i) {
                const cs_arm64_op& op = insn->detail->arm64.operands[i];
                if (op.type != ARM64_OP_IMM) {
                    continue;
                }
                const auto imm = static_cast<uint64_t>(op.imm);
                if (branch && !item.target) {
                    item.target = imm;
                } else if (!branch && section_containing(*session.program, imm) != nullptr) {
                    item.mem_refs.push_back(imm);
                }
            }
        }
        if ((item.flow == Flow::Jump || item.flow == Flow::CondJump || item.flow == Flow::Call) && !item.target) {
            if (const auto parsed = parse_hex_token(insn->op_str)) {
                item.target = *parsed;
            } else {
                item.indirect = true;
            }
        }
        out = std::move(item);
    }
    cs_free(insn, 1);
    return out;
}

void enqueue(Session& session, uint64_t address, bool entry) {
    if (!in_exec(*session.program, address)) {
        return;
    }
    if (entry) {
        session.entries.insert(address);
    }
    if (session.queued.insert(address).second) {
        session.work.push_back(address);
    }
}

void linear(Session& session, uint64_t address) {
    while (session.insns.size() < session.cap) {
        if (session.insns.find(address) != session.insns.end()) {
            return;
        }
        auto decoded = decode_at(session, address);
        if (!decoded) {
            return;
        }
        const Instruction insn = *decoded;
        session.insns.emplace(insn.address, insn);
        const auto next = checked_add(insn.address, insn.size);
        if (insn.flow == Flow::Jump || insn.flow == Flow::Return || insn.flow == Flow::Interrupt) {
            if (insn.target) {
                enqueue(session, *insn.target, false);
            }
            return;
        }
        if (insn.flow == Flow::CondJump && insn.target) {
            enqueue(session, *insn.target, false);
        }
        if (insn.flow == Flow::Call && insn.target) {
            enqueue(session, *insn.target, true);
        }
        if (!next || exec_section(*session.program, *next) == nullptr) {
            return;
        }
        address = *next;
    }
    session.truncated = true;
}

void scan_prologues(Session& session) {
    const unsigned step_fail = (session.program->arch == Arch::Arm || session.program->arch == Arch::Arm64) ? 4 : 1;
    for (const auto& section : session.program->sections) {
        if (!section.executable || section.bytes.empty()) {
            continue;
        }
        uint64_t address = section.va;
        const uint64_t end = section.va + section.bytes.size();
        while (address < end && session.insns.size() < session.cap) {
            if (const auto it = session.insns.find(address); it != session.insns.end()) {
                address += it->second.size == 0 ? step_fail : it->second.size;
                continue;
            }
            auto decoded = decode_at(session, address);
            if (!decoded) {
                if (address > end - step_fail) {
                    break;
                }
                address += step_fail;
                continue;
            }
            if (is_prologue(session.program->arch, *decoded)) {
                enqueue(session, address, true);
                linear(session, address);
            }
            address += decoded->size == 0 ? step_fail : decoded->size;
        }
    }
}

void build_functions(Program& program, const std::map<uint64_t, Instruction>& insns, const std::set<uint64_t>& entries) {
    std::vector<uint64_t> starts;
    for (uint64_t entry : entries) {
        if (insns.find(entry) != insns.end()) {
            starts.push_back(entry);
        }
    }
    std::unordered_map<uint64_t, std::string> names;
    for (const auto& symbol : program.symbols) {
        if (!symbol.imported && !symbol.name.empty()) {
            names.emplace(symbol.address, symbol.display.empty() ? symbol.name : symbol.display);
        }
    }
    for (size_t i = 0; i < starts.size(); ++i) {
        const uint64_t begin = starts[i];
        const uint64_t end = (i + 1 < starts.size()) ? starts[i + 1] : UINT64_MAX;
        Function function;
        function.address = begin;
        function.end = end;
        if (const auto it = names.find(begin); it != names.end()) {
            function.name = it->second;
        } else {
            function.name = "sub_" + hex_addr(begin).substr(2);
        }
        std::vector<Instruction> body;
        for (auto it = insns.lower_bound(begin); it != insns.end() && it->first < end; ++it) {
            body.push_back(it->second);
            if (it->second.flow == Flow::Call && it->second.target) {
                function.calls.push_back(*it->second.target);
            }
        }
        if (body.empty()) {
            continue;
        }
        std::set<uint64_t> leaders;
        leaders.insert(begin);
        auto in_body = [&](uint64_t address) {
            return address >= begin && address < end && insns.find(address) != insns.end();
        };
        for (const auto& insn : body) {
            const auto next = checked_add(insn.address, insn.size);
            if (insn.flow == Flow::CondJump || insn.flow == Flow::Jump) {
                if (insn.target && in_body(*insn.target)) {
                    leaders.insert(*insn.target);
                }
            }
            if ((insn.flow == Flow::CondJump || insn.flow == Flow::Return || insn.flow == Flow::Interrupt) && next &&
                in_body(*next)) {
                leaders.insert(*next);
            }
        }
        std::vector<uint64_t> leader_list(leaders.begin(), leaders.end());
        for (size_t b = 0; b < leader_list.size(); ++b) {
            BasicBlock block;
            block.start = leader_list[b];
            const uint64_t stop = (b + 1 < leader_list.size()) ? leader_list[b + 1] : end;
            const Instruction* last = nullptr;
            for (auto it = insns.find(block.start); it != insns.end() && it->first < stop && it->first < end; ++it) {
                block.instructions.push_back(it->first);
                last = &it->second;
                if (it->second.flow == Flow::Jump || it->second.flow == Flow::CondJump ||
                    it->second.flow == Flow::Return || it->second.flow == Flow::Interrupt) {
                    break;
                }
            }
            if (block.instructions.empty() || last == nullptr) {
                continue;
            }
            const auto fall = checked_add(last->address, last->size);
            if (last->flow == Flow::CondJump) {
                if (last->target && in_body(*last->target)) {
                    block.succs.push_back(*last->target);
                }
                if (fall && in_body(*fall)) {
                    block.succs.push_back(*fall);
                }
            } else if (last->flow == Flow::Jump) {
                if (last->target && in_body(*last->target)) {
                    block.succs.push_back(*last->target);
                }
            } else if (last->flow != Flow::Return && last->flow != Flow::Interrupt && fall && in_body(*fall)) {
                block.succs.push_back(*fall);
            }
            function.blocks.push_back(std::move(block));
        }
        program.functions.push_back(std::move(function));
    }
}

bool open_engine(Arch arch, Engine& engine, std::string& error) {
    cs_arch csarch = CS_ARCH_ARM64;
    cs_mode mode = CS_MODE_LITTLE_ENDIAN;
    switch (arch) {
    case Arch::X86:
        csarch = CS_ARCH_X86;
        mode = CS_MODE_32;
        break;
    case Arch::X64:
        csarch = CS_ARCH_X86;
        mode = CS_MODE_64;
        break;
    case Arch::Arm:
        csarch = CS_ARCH_ARM;
        mode = CS_MODE_ARM;
        break;
    case Arch::Arm64:
        csarch = CS_ARCH_ARM64;
        mode = CS_MODE_LITTLE_ENDIAN;
        break;
    case Arch::Unknown:
        error = "disassembly skipped: unknown architecture";
        return false;
    }
    if (cs_open(csarch, mode, &engine.handle) != CS_ERR_OK) {
        error = "capstone refused this architecture";
        return false;
    }
    engine.open = true;
    cs_option(engine.handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (arch == Arch::X86 || arch == Arch::X64) {
        cs_option(engine.handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    }
    return true;
}

}  // namespace

const Section* section_containing(const Program& program, uint64_t address) {
    const Section* found = nullptr;
    for (const auto& section : program.sections) {
        const uint64_t span = std::max(section.virtual_size, static_cast<uint64_t>(section.bytes.size()));
        if (span == 0 || address < section.va || address - section.va >= span) {
            continue;
        }
        if (found == nullptr || section.executable) {
            found = &section;
        }
    }
    return found;
}

const Instruction* find_insn(const Program& program, uint64_t address) {
    const auto it = program.insn_index.find(address);
    if (it == program.insn_index.end() || it->second >= program.instructions.size()) {
        return nullptr;
    }
    return &program.instructions[it->second];
}

std::optional<Instruction> disassemble_one(Arch arch, uint64_t address, const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || arch == Arch::Unknown) {
        return std::nullopt;
    }
    Engine engine;
    std::string error;
    if (!open_engine(arch, engine, error)) {
        return std::nullopt;
    }
    const uint8_t* code = data;
    size_t left = size;
    uint64_t cursor = address;
    cs_insn* insn = cs_malloc(engine.handle);
    if (insn == nullptr) {
        return std::nullopt;
    }
    std::optional<Instruction> out;
    if (cs_disasm_iter(engine.handle, &code, &left, &cursor, insn) && insn->size > 0) {
        Instruction item;
        item.address = insn->address;
        item.size = insn->size;
        item.mnemonic = insn->mnemonic;
        item.op_str = insn->op_str;
        item.bytes.assign(insn->bytes, insn->bytes + std::min<uint16_t>(insn->size, 24));
        item.flow = classify(engine.handle, *insn);
        out = std::move(item);
    }
    cs_free(insn, 1);
    return out;
}

void disassemble_program(Program& program, const Options& options) {
    program.instructions.clear();
    program.functions.clear();
    program.insn_index.clear();
    if (program.arch == Arch::Unknown) {
        program.notes.push_back("disassembly skipped: unknown architecture");
        return;
    }
    Engine engine;
    std::string error;
    if (!open_engine(program.arch, engine, error)) {
        program.notes.push_back(error);
        return;
    }
    Session session;
    session.program = &program;
    session.engine = &engine;
    session.cap = options.max_instructions;
    if (program.entry_known) {
        enqueue(session, program.entry, true);
    }
    for (const auto& symbol : program.symbols) {
        if (symbol.function && !symbol.imported) {
            enqueue(session, symbol.address, true);
        }
    }
    for (uint64_t start : program.function_starts) {
        enqueue(session, start, true);
    }
    while (!session.work.empty() && session.insns.size() < session.cap) {
        const uint64_t address = session.work.front();
        session.work.pop_front();
        linear(session, address);
    }
    scan_prologues(session);
    while (!session.work.empty() && session.insns.size() < session.cap) {
        const uint64_t address = session.work.front();
        session.work.pop_front();
        linear(session, address);
    }
    if (session.truncated) {
        program.notes.push_back("instruction cap reached (" + std::to_string(options.max_instructions) + ")");
    }
    program.instructions.reserve(session.insns.size());
    for (const auto& [address, insn] : session.insns) {
        program.insn_index.emplace(address, static_cast<uint32_t>(program.instructions.size()));
        program.instructions.push_back(insn);
        (void)address;
    }
    build_functions(program, session.insns, session.entries);
}

}  // namespace fathom
