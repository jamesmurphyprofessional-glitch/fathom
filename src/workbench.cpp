#include "fathom/engine.hpp"
#include "fathom/util.hpp"
#include "fathom/workbench.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <cctype>

namespace fathom {
namespace {

std::string lower_copy(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

bool matches(std::string_view label, uint64_t address, const std::string& filter) {
    if (filter.empty()) {
        return true;
    }
    const std::string folded = lower_copy(filter);
    if (lower_copy(label).find(folded) != std::string::npos) {
        return true;
    }
    return lower_copy(hex_addr(address)).find(folded) != std::string::npos;
}

const char* arch_label_of(Arch arch) {
    switch (arch) {
    case Arch::X86:
        return "x86";
    case Arch::X64:
        return "x86_64";
    case Arch::Arm:
        return "arm";
    case Arch::Arm64:
        return "arm64";
    case Arch::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* format_label_of(Format format) {
    switch (format) {
    case Format::MachO:
        return "Mach-O";
    case Format::Elf:
        return "ELF";
    case Format::Pe:
        return "PE";
    case Format::Coff:
        return "COFF";
    case Format::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* xref_label(XrefKind kind) {
    switch (kind) {
    case XrefKind::Call:
        return "call";
    case XrefKind::Jump:
        return "jump";
    case XrefKind::Data:
        return "data";
    case XrefKind::String:
        return "string";
    }
    return "data";
}

std::string byte_text(const std::vector<uint8_t>& bytes) {
    std::string out;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            out.push_back(' ');
        }
        out += fmt::format("{:02x}", bytes[i]);
    }
    return out;
}

const Function* function_at(const Program& program, uint64_t address) {
    const Function* found = nullptr;
    for (const auto& function : program.functions) {
        if (address == function.address) {
            found = &function;
        }
        for (const auto& block : function.blocks) {
            if (block.instructions.empty()) {
                continue;
            }
            const uint64_t begin = block.instructions.front();
            const Instruction* last = find_insn(program, block.instructions.back());
            const uint64_t end = last == nullptr ? block.instructions.back() + 1
                                                 : last->address + std::max<uint16_t>(last->size, 1);
            if (address >= begin && address < end) {
                found = &function;
            }
        }
    }
    return found;
}

}  // namespace

void Workbench::set_program(Program program) {
    program_ = std::move(program);
    open_ = true;
    filter_.clear();
    if (program_.entry_known) {
        select(program_.entry);
        return;
    }
    if (!program_.functions.empty()) {
        select(program_.functions.front().address);
        return;
    }
    cursor_known_ = false;
    cursor_ = 0;
}

bool Workbench::has_program() const {
    return open_;
}

const Program& Workbench::program() const {
    return program_;
}

std::string Workbench::arch_label() const {
    return open_ ? arch_label_of(program_.arch) : "unknown";
}

std::string Workbench::format_label() const {
    if (!open_) {
        return "unknown";
    }
    if (!program_.format_name.empty()) {
        return program_.format_name;
    }
    return format_label_of(program_.format);
}

uint64_t Workbench::cursor() const {
    return cursor_;
}

bool Workbench::cursor_known() const {
    return cursor_known_;
}

void Workbench::set_filter(std::string filter) {
    filter_ = std::move(filter);
}

const std::string& Workbench::filter() const {
    return filter_;
}

std::vector<FunctionRow> Workbench::functions() const {
    std::vector<FunctionRow> rows;
    if (!open_) {
        return rows;
    }
    rows.reserve(program_.functions.size());
    for (const auto& function : program_.functions) {
        if (!matches(function.name, function.address, filter_)) {
            continue;
        }
        rows.push_back({function.address, function.name, function.blocks.size()});
    }
    std::sort(rows.begin(), rows.end(), [](const FunctionRow& a, const FunctionRow& b) {
        return a.address < b.address;
    });
    return rows;
}

std::vector<StringRow> Workbench::strings() const {
    std::vector<StringRow> rows;
    if (!open_) {
        return rows;
    }
    for (const auto& item : program_.strings) {
        if (!matches(item.text, item.address, filter_)) {
            continue;
        }
        rows.push_back({item.address, item.text, item.utf16});
    }
    return rows;
}

std::vector<TriageRow> Workbench::triage() const {
    std::vector<TriageRow> rows;
    if (!open_) {
        return rows;
    }
    for (const auto& finding : program_.findings) {
        rows.push_back({finding.severity, finding.category, finding.detail});
    }
    return rows;
}

void Workbench::select(uint64_t address) {
    cursor_ = address;
    cursor_known_ = true;
}

const Function* Workbench::current_function() const {
    if (!open_ || !cursor_known_) {
        return nullptr;
    }
    return function_at(program_, cursor_);
}

std::vector<DisasmRow> Workbench::disassembly() const {
    std::vector<DisasmRow> rows;
    const Function* function = current_function();
    if (function == nullptr) {
        return rows;
    }
    for (const auto& block : function->blocks) {
        for (uint64_t address : block.instructions) {
            const Instruction* insn = find_insn(program_, address);
            if (insn == nullptr) {
                continue;
            }
            DisasmRow row;
            row.address = insn->address;
            row.bytes = byte_text(insn->bytes);
            row.mnemonic = insn->mnemonic;
            row.operands = insn->op_str;
            row.call = insn->flow == Flow::Call;
            row.jump = insn->flow == Flow::Jump || insn->flow == Flow::CondJump;
            row.ret = insn->flow == Flow::Return;
            rows.push_back(std::move(row));
        }
    }
    return rows;
}

std::string Workbench::listing() const {
    const Function* function = current_function();
    if (function == nullptr) {
        return "no function to list\n";
    }
    return render_decompile(program_, hex_addr(function->address));
}

std::vector<HexLine> Workbench::hex(size_t byte_count) const {
    std::vector<HexLine> lines;
    if (!open_ || !cursor_known_ || byte_count == 0) {
        return lines;
    }
    const Section* section = section_containing(program_, cursor_);
    if (section == nullptr || cursor_ < section->va || cursor_ - section->va >= section->bytes.size()) {
        return lines;
    }
    const uint64_t section_end = section->va + section->bytes.size();
    const size_t row_count = std::max<size_t>(byte_count / 16, 1);
    const uint64_t cursor_row = cursor_ & ~uint64_t{15};
    uint64_t start = cursor_row;
    const size_t before = row_count / 2;
    for (size_t i = 0; i < before; ++i) {
        if (start < 16 || start - 16 < section->va) {
            break;
        }
        start -= 16;
    }
    if (start < section->va) {
        start = section->va & ~uint64_t{15};
    }
    for (size_t n = 0; n < row_count; ++n) {
        const uint64_t row = start + static_cast<uint64_t>(n) * 16;
        if (row >= section_end) {
            break;
        }
        HexLine line;
        line.address = row;
        line.cells.resize(16);
        for (int i = 0; i < 16; ++i) {
            const uint64_t address = row + static_cast<uint64_t>(i);
            HexCell cell;
            cell.address = address;
            if (address >= section->va && address < section_end) {
                cell.present = true;
                cell.value = section->bytes[static_cast<size_t>(address - section->va)];
                line.ascii.push_back(cell.value >= 0x20 && cell.value <= 0x7e ? static_cast<char>(cell.value) : '.');
            } else {
                line.ascii.push_back(' ');
            }
            line.cells[static_cast<size_t>(i)] = cell;
        }
        lines.push_back(std::move(line));
    }
    return lines;
}

std::vector<GraphBlock> Workbench::graph() const {
    std::vector<GraphBlock> blocks;
    const Function* function = current_function();
    if (function == nullptr) {
        return blocks;
    }
    for (const auto& block : function->blocks) {
        GraphBlock item;
        item.start = block.start;
        item.succs = block.succs;
        size_t shown = 0;
        for (uint64_t address : block.instructions) {
            if (shown == 24) {
                item.lines.emplace_back("...");
                break;
            }
            if (const Instruction* insn = find_insn(program_, address)) {
                std::string line = insn->mnemonic;
                if (!insn->op_str.empty()) {
                    line.push_back(' ');
                    line += insn->op_str;
                }
                item.lines.push_back(std::move(line));
            }
            ++shown;
        }
        blocks.push_back(std::move(item));
    }
    return blocks;
}

std::vector<XrefRow> Workbench::xrefs() const {
    std::vector<XrefRow> rows;
    if (!open_ || !cursor_known_) {
        return rows;
    }
    for (const auto& xref : program_.xrefs) {
        if (xref.to != cursor_) {
            continue;
        }
        rows.push_back({xref.from, xref.to, xref_label(xref.kind)});
    }
    return rows;
}

LowerView Workbench::lower() const {
    return lower_;
}

void Workbench::set_lower(LowerView view) {
    lower_ = view;
}

}  // namespace fathom
