#pragma once

#include "fathom/program.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace fathom {

enum class LowerView { Hex, Graph };

struct FunctionRow {
    uint64_t address = 0;
    std::string name;
    size_t blocks = 0;
};

struct StringRow {
    uint64_t address = 0;
    std::string text;
    bool utf16 = false;
};

struct TriageRow {
    std::string severity;
    std::string category;
    std::string detail;
};

struct DisasmRow {
    uint64_t address = 0;
    std::string bytes;
    std::string mnemonic;
    std::string operands;
    bool call = false;
    bool jump = false;
    bool ret = false;
};

struct HexCell {
    uint64_t address = 0;
    uint8_t value = 0;
    bool present = false;
};

struct HexLine {
    uint64_t address = 0;
    std::vector<HexCell> cells;
    std::string ascii;
};

struct GraphBlock {
    uint64_t start = 0;
    std::vector<std::string> lines;
    std::vector<uint64_t> succs;
};

struct XrefRow {
    uint64_t from = 0;
    uint64_t to = 0;
    std::string kind;
};

class Workbench {
public:
    void set_program(Program program);
    bool has_program() const;
    const Program& program() const;

    std::string arch_label() const;
    std::string format_label() const;
    uint64_t cursor() const;
    bool cursor_known() const;

    void set_filter(std::string filter);
    const std::string& filter() const;

    std::vector<FunctionRow> functions() const;
    std::vector<StringRow> strings() const;
    std::vector<TriageRow> triage() const;

    void select(uint64_t address);
    const Function* current_function() const;

    std::vector<DisasmRow> disassembly() const;
    std::string listing() const;
    std::vector<HexLine> hex(size_t byte_count = 256) const;
    std::vector<GraphBlock> graph() const;
    std::vector<XrefRow> xrefs() const;

    LowerView lower() const;
    void set_lower(LowerView view);

private:
    Program program_;
    bool open_ = false;
    uint64_t cursor_ = 0;
    bool cursor_known_ = false;
    std::string filter_;
    LowerView lower_ = LowerView::Hex;
};

}  // namespace fathom
