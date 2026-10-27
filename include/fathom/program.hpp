#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace fathom {

inline constexpr const char* kVersion = "0.1.0";
inline constexpr const char* kRetSyncUpstream = "https://github.com/bootleg/ret-sync";

// Failures the user can act on: a missing file, a refused port, a debugger that
// will not start. Analysis of hostile bytes is reported on Program::notes.
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class Arch { Unknown, X86, X64, Arm, Arm64 };
enum class Format { Unknown, MachO, Elf, Pe, Coff };

enum class Flow { Fallthrough, Jump, CondJump, Call, Return, Interrupt };

struct Section {
    std::string name;
    uint64_t index = 0;
    uint64_t va = 0;
    uint64_t file_offset = 0;
    uint64_t virtual_size = 0;
    std::vector<uint8_t> bytes;
    bool executable = false;
    bool writable = false;
    bool readable = true;
    double entropy = 0;
};

struct Symbol {
    std::string name;
    std::string display;
    uint64_t address = 0;
    bool function = false;
    bool imported = false;
    bool exported = false;
    std::string library;
};

struct Import {
    std::string library;
    std::string name;
    bool delayed = false;
    bool ordinal = false;
    uint16_t ordinal_value = 0;
};

struct Instruction {
    uint64_t address = 0;
    uint16_t size = 0;
    std::string mnemonic;
    std::string op_str;
    std::vector<uint8_t> bytes;
    Flow flow = Flow::Fallthrough;
    std::optional<uint64_t> target;
    bool indirect = false;
    std::vector<uint64_t> mem_refs;
};

struct BasicBlock {
    uint64_t start = 0;
    std::vector<uint64_t> instructions;
    std::vector<uint64_t> succs;
};

struct Function {
    uint64_t address = 0;
    uint64_t end = 0;
    std::string name;
    std::vector<BasicBlock> blocks;
    std::vector<uint64_t> calls;
};

enum class XrefKind { Call, Jump, Data, String };

struct Xref {
    uint64_t from = 0;
    uint64_t to = 0;
    XrefKind kind = XrefKind::Data;
};

struct FoundString {
    uint64_t address = 0;
    std::string text;
    bool utf16 = false;
    std::string section;
};

struct VTable {
    uint64_t address = 0;
    std::string name;
    std::vector<uint64_t> slots;
    std::string source;
};

struct Finding {
    std::string severity;
    std::string category;
    std::string detail;
};

struct Comment {
    uint64_t address = 0;
    std::string text;
    std::string source;
};

struct Program {
    std::string path;
    std::string format_name;
    Format format = Format::Unknown;
    Arch arch = Arch::Unknown;
    int address_size = 8;
    uint64_t entry = 0;
    bool entry_known = false;
    uint64_t image_base = 0;
    uint64_t image_size = 0;
    bool relocatable = false;
    bool encrypted = false;
    std::string uuid;
    std::string slice;
    std::vector<std::string> libraries;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<Import> imports;
    std::vector<Symbol> exports;
    std::vector<uint64_t> function_starts;
    std::vector<Instruction> instructions;
    std::unordered_map<uint64_t, uint32_t> insn_index;
    std::vector<Function> functions;
    std::vector<Xref> xrefs;
    std::vector<FoundString> strings;
    std::vector<VTable> vtables;
    std::vector<Finding> findings;
    std::vector<Comment> comments;
    std::vector<std::string> notes;
    uint64_t file_size = 0;
    uint64_t overlay_size = 0;
    std::vector<uint8_t> file_bytes;
};

struct Options {
    uint64_t max_file_bytes = 256ull * 1024ull * 1024ull;
    uint64_t max_instructions = 1000000;
    uint64_t max_xrefs = 250000;
    uint64_t max_strings = 100000;
    int min_string = 4;
    std::string slice;
};

const Instruction* find_insn(const Program& program, uint64_t address);
const Section* section_containing(const Program& program, uint64_t address);

}  // namespace fathom
