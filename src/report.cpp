#include "fathom/engine.hpp"
#include "fathom/util.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <sstream>

namespace fathom {
namespace {

const char* arch_name(Arch arch) {
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

const char* format_label(Format format) {
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

const char* xref_name(XrefKind kind) {
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

int severity_rank(std::string_view severity) {
    if (severity == "high") {
        return 3;
    }
    if (severity == "medium") {
        return 2;
    }
    if (severity == "low") {
        return 1;
    }
    return 0;
}

std::string hex_bytes(const std::vector<uint8_t>& bytes) {
    std::string out;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            out.push_back(' ');
        }
        out += fmt::format("{:02x}", bytes[i]);
    }
    return out;
}

const Function* function_covering(const Program& program, uint64_t address) {
    const Function* found = nullptr;
    for (const auto& function : program.functions) {
        if (address >= function.address && address < function.end) {
            found = &function;
        }
    }
    return found;
}

}  // namespace

const Symbol* find_symbol(const Program& program, std::string_view name) {
    const Symbol* loose = nullptr;
    for (const auto& symbol : program.symbols) {
        if (symbol.name == name || symbol.display == name) {
            return &symbol;
        }
        if (iequals(symbol.name, name) || iequals(symbol.display, name)) {
            loose = &symbol;
        }
        if (!symbol.name.empty() && symbol.name.front() == '_' &&
            (symbol.name.substr(1) == name || iequals(symbol.name.substr(1), name))) {
            loose = &symbol;
        }
    }
    return loose;
}

const Function* find_function(const Program& program, const std::string& name_or_addr) {
    if (name_or_addr.empty()) {
        if (program.entry_known) {
            if (const Function* function = function_covering(program, program.entry)) {
                return function;
            }
        }
        return program.functions.empty() ? nullptr : &program.functions.front();
    }
    if (const auto address = parse_address(name_or_addr)) {
        for (const auto& function : program.functions) {
            if (function.address == *address) {
                return &function;
            }
        }
        return function_covering(program, *address);
    }
    for (const auto& function : program.functions) {
        if (function.name == name_or_addr || iequals(function.name, name_or_addr)) {
            return &function;
        }
    }
    if (const Symbol* symbol = find_symbol(program, name_or_addr)) {
        for (const auto& function : program.functions) {
            if (function.address == symbol->address) {
                return &function;
            }
        }
    }
    return nullptr;
}

std::string render_summary(const Program& program) {
    std::ostringstream out;
    out << "fathom " << kVersion << "\n";
    out << "file        " << program.path << "\n";
    out << "format      " << (program.format_name.empty() ? format_label(program.format) : program.format_name)
        << "\n";
    out << "arch        " << arch_name(program.arch) << "\n";
    out << "image base  " << hex_addr(program.image_base) << "\n";
    out << "entry       " << (program.entry_known ? hex_addr(program.entry) : "unknown") << "\n";
    out << "size        " << program.file_size << " bytes\n";
    if (!program.uuid.empty()) {
        out << "uuid        " << program.uuid << "\n";
    }
    if (!program.slice.empty()) {
        out << "slice       " << program.slice << "\n";
    }
    out << "sections    " << program.sections.size() << "\n";
    out << "symbols     " << program.symbols.size() << "\n";
    out << "imports     " << program.imports.size() << "\n";
    out << "functions   " << program.functions.size() << "\n";
    out << "instructions " << program.instructions.size() << "\n";
    out << "strings     " << program.strings.size() << "\n";
    out << "xrefs       " << program.xrefs.size() << "\n";
    out << "vtables     " << program.vtables.size() << "\n";
    int shown = 0;
    for (const auto& finding : program.findings) {
        if (severity_rank(finding.severity) < 2) {
            continue;
        }
        if (shown == 0) {
            out << "findings\n";
        }
        out << "  [" << finding.severity << "] " << finding.category << ": " << finding.detail << "\n";
        ++shown;
    }
    if (shown == 0) {
        out << "findings    none at medium or high\n";
    }
    for (const auto& note : program.notes) {
        out << "note        " << note << "\n";
    }
    return out.str();
}

std::string render_triage(const Program& program) {
    std::ostringstream out;
    if (program.findings.empty()) {
        out << "no triage findings\n";
        return out.str();
    }
    for (const auto& finding : program.findings) {
        out << "[" << finding.severity << "] " << finding.category << ": " << finding.detail << "\n";
    }
    return out.str();
}

std::string render_functions(const Program& program) {
    std::ostringstream out;
    for (const auto& function : program.functions) {
        out << hex_addr(function.address) << "  " << function.name << "  blocks=" << function.blocks.size()
            << " calls=" << function.calls.size() << "\n";
    }
    if (program.functions.empty()) {
        out << "no functions recovered\n";
    }
    return out.str();
}

std::string render_strings(const Program& program, size_t limit) {
    std::ostringstream out;
    size_t shown = 0;
    for (const auto& item : program.strings) {
        if (shown >= limit) {
            out << "... " << (program.strings.size() - shown) << " more\n";
            break;
        }
        out << hex_addr(item.address) << (item.utf16 ? "  utf16  " : "  ascii  ") << item.text << "\n";
        ++shown;
    }
    return out.str();
}

std::string render_disasm(const Program& program, const std::string& func, size_t limit) {
    std::ostringstream out;
    std::vector<const Instruction*> rows;
    if (!func.empty() || !program.functions.empty()) {
        if (const Function* function = find_function(program, func)) {
            out << function->name << " " << hex_addr(function->address) << "\n";
            for (const auto& block : function->blocks) {
                for (uint64_t address : block.instructions) {
                    if (const Instruction* insn = find_insn(program, address)) {
                        rows.push_back(insn);
                    }
                }
            }
        } else if (!func.empty()) {
            return "no function named " + func + "\n";
        }
    }
    if (rows.empty()) {
        for (const auto& insn : program.instructions) {
            rows.push_back(&insn);
            if (rows.size() >= limit) {
                break;
            }
        }
    }
    size_t shown = 0;
    for (const Instruction* insn : rows) {
        if (shown >= limit) {
            out << "... truncated\n";
            break;
        }
        out << fmt::format("{}  {:24}  {} {}\n", hex_addr(insn->address), hex_bytes(insn->bytes), insn->mnemonic,
                           insn->op_str);
        ++shown;
    }
    if (shown == 0) {
        out << "no instructions\n";
    }
    return out.str();
}

std::string render_decompile(const Program& program, const std::string& func) {
    const Function* function = find_function(program, func);
    if (function == nullptr) {
        return "no function to list\n";
    }
    std::ostringstream out;
    out << "// structural listing for " << function->name << "\n";
    out << "// This is not Hex-Rays decompilation and it does not load HexRaysCodeXplorer.\n";
    out << function->name << " {\n";
    for (const auto& block : function->blocks) {
        out << hex_addr(block.start) << ":\n";
        for (uint64_t address : block.instructions) {
            const Instruction* insn = find_insn(program, address);
            if (insn == nullptr) {
                continue;
            }
            if (insn->flow == Flow::CondJump && insn->target) {
                out << "    if (" << insn->mnemonic << " " << insn->op_str << ") goto " << hex_addr(*insn->target)
                    << ";\n";
            } else if (insn->flow == Flow::Jump && insn->target) {
                out << "    goto " << hex_addr(*insn->target) << ";\n";
            } else if (insn->flow == Flow::Return) {
                out << "    return;\n";
            } else if (insn->flow == Flow::Call) {
                out << "    call " << (insn->target ? hex_addr(*insn->target) : insn->op_str) << ";\n";
            } else {
                out << "    " << insn->mnemonic;
                if (!insn->op_str.empty()) {
                    out << " " << insn->op_str;
                }
                out << ";\n";
            }
        }
    }
    out << "}\n";
    return out.str();
}

std::string render_xrefs(const Program& program, const std::string& target) {
    const auto address = parse_address(target);
    uint64_t want = 0;
    bool have = false;
    if (address) {
        want = *address;
        have = true;
    } else if (const Symbol* symbol = find_symbol(program, target)) {
        want = symbol->address;
        have = true;
    } else if (const Function* function = find_function(program, target)) {
        want = function->address;
        have = true;
    }
    if (!have) {
        return "unknown target " + target + "\n";
    }
    std::ostringstream out;
    size_t count = 0;
    for (const auto& xref : program.xrefs) {
        if (xref.to != want && !(xref.to >= want && xref.to < want + 64 && target.empty())) {
            if (xref.to != want) {
                continue;
            }
        }
        if (xref.to != want) {
            continue;
        }
        out << xref_name(xref.kind) << "  " << hex_addr(xref.from) << " -> " << hex_addr(xref.to) << "\n";
        ++count;
    }
    if (count == 0) {
        out << "no cross-references to " << hex_addr(want) << "\n";
    }
    return out.str();
}

std::string render_cfg(const Program& program, const std::string& func) {
    const Function* function = find_function(program, func);
    if (function == nullptr) {
        return "no function\n";
    }
    std::ostringstream out;
    out << function->name << "\n";
    for (const auto& block : function->blocks) {
        out << "  " << hex_addr(block.start) << " ->";
        for (uint64_t succ : block.succs) {
            out << " " << hex_addr(succ);
        }
        out << "\n";
    }
    return out.str();
}

std::string render_dot(const Program& program, const std::string& func) {
    const Function* function = find_function(program, func);
    if (function == nullptr) {
        return "digraph {}\n";
    }
    std::ostringstream out;
    out << "digraph \"" << dot_escape(function->name) << "\" {\n";
    out << "  node [shape=box fontname=\"Menlo\"];\n";
    for (const auto& block : function->blocks) {
        std::string label = hex_addr(block.start);
        size_t shown = 0;
        for (uint64_t address : block.instructions) {
            if (shown == 8) {
                label += "\\n...";
                break;
            }
            if (const Instruction* insn = find_insn(program, address)) {
                label += "\\n" + dot_escape(insn->mnemonic + " " + insn->op_str);
            }
            ++shown;
        }
        out << "  \"" << hex_addr(block.start) << "\" [label=\"" << label << "\"];\n";
        for (uint64_t succ : block.succs) {
            out << "  \"" << hex_addr(block.start) << "\" -> \"" << hex_addr(succ) << "\";\n";
        }
    }
    out << "}\n";
    return out.str();
}

std::string render_objects(const Program& program) {
    std::ostringstream out;
    out << "virtual tables\n";
    if (program.vtables.empty()) {
        out << "  none\n";
    }
    for (const auto& table : program.vtables) {
        out << hex_addr(table.address) << "  " << table.name << "  " << table.source << "  slots="
            << table.slots.size() << "\n";
        size_t shown = 0;
        for (uint64_t slot : table.slots) {
            if (shown == 16) {
                out << "    ...\n";
                break;
            }
            out << "    [" << shown << "] " << hex_addr(slot) << "\n";
            ++shown;
        }
    }
    out << "rtti-like strings\n";
    size_t names = 0;
    for (const auto& item : program.strings) {
        if (!(item.text.starts_with("_ZTS") || item.text.starts_with(".?AV") || item.text.starts_with("_ZTV"))) {
            continue;
        }
        out << "  " << hex_addr(item.address) << "  " << item.text << "\n";
        if (++names == 200) {
            break;
        }
    }
    if (names == 0) {
        out << "  none\n";
    }
    return out.str();
}

std::string render_hex(const Program& program, uint64_t origin, bool by_va, size_t length) {
    length = std::min(length, static_cast<size_t>(65536));
    const uint8_t* data = nullptr;
    size_t available = 0;
    uint64_t display = origin;
    if (by_va) {
        const Section* section = section_containing(program, origin);
        if (section == nullptr || origin < section->va || origin - section->va >= section->bytes.size()) {
            return "address is not in a file-backed section\n";
        }
        const size_t offset = static_cast<size_t>(origin - section->va);
        data = section->bytes.data() + offset;
        available = section->bytes.size() - offset;
    } else {
        if (origin > program.file_bytes.size()) {
            return "offset is past the end of the file\n";
        }
        const size_t offset = static_cast<size_t>(origin);
        data = program.file_bytes.data() + offset;
        available = program.file_bytes.size() - offset;
    }
    const size_t n = std::min(length, available);
    std::ostringstream out;
    for (size_t i = 0; i < n; i += 16) {
        out << hex_addr(display + i) << "  ";
        std::string ascii;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < n) {
                const unsigned char byte = data[i + j];
                out << fmt::format("{:02x} ", byte);
                ascii.push_back(byte >= 0x20 && byte <= 0x7e ? static_cast<char>(byte) : '.');
            } else {
                out << "   ";
            }
        }
        out << " " << ascii << "\n";
    }
    if (n == 0) {
        out << "no bytes\n";
    }
    return out.str();
}

std::string render_find_text(const Program& program, const std::string& needle) {
    if (needle.empty()) {
        return "empty search\n";
    }
    const auto* begin = program.file_bytes.data();
    const auto* end = begin + program.file_bytes.size();
    std::ostringstream out;
    size_t found = 0;
    const auto* cursor = begin;
    while (cursor < end && found < 100) {
        const auto* hit = std::search(cursor, end, needle.begin(), needle.end());
        if (hit == end) {
            break;
        }
        const uint64_t offset = static_cast<uint64_t>(hit - begin);
        out << "file+" << hex_addr(offset) << "\n";
        cursor = hit + 1;
        ++found;
    }
    if (found == 0) {
        out << "not found\n";
    }
    return out.str();
}

std::string render_find_bytes(const Program& program, const std::vector<uint8_t>& needle) {
    if (needle.empty()) {
        return "empty search\n";
    }
    const auto* begin = program.file_bytes.data();
    const auto* end = begin + program.file_bytes.size();
    std::ostringstream out;
    size_t found = 0;
    const auto* cursor = begin;
    while (cursor < end && found < 100) {
        const auto* hit = std::search(cursor, end, needle.begin(), needle.end());
        if (hit == end) {
            break;
        }
        out << "file+" << hex_addr(static_cast<uint64_t>(hit - begin)) << "\n";
        cursor = hit + 1;
        ++found;
    }
    if (found == 0) {
        out << "not found\n";
    }
    return out.str();
}

std::string render_json(const Program& program) {
    nlohmann::json root;
    root["tool"] = "fathom";
    root["version"] = kVersion;
    root["path"] = program.path;
    root["format"] = format_label(program.format);
    root["format_detail"] = program.format_name;
    root["arch"] = arch_name(program.arch);
    root["image_base"] = hex_addr(program.image_base);
    if (program.entry_known) {
        root["entry"] = hex_addr(program.entry);
    } else {
        root["entry"] = nlohmann::json();
    }
    root["file_size"] = program.file_size;
    root["overlay"] = program.overlay_size;
    root["uuid"] = program.uuid;
    root["encrypted"] = program.encrypted;
    root["libraries"] = program.libraries;
    root["notes"] = program.notes;
    root["counts"] = {{"sections", program.sections.size()},
                      {"symbols", program.symbols.size()},
                      {"imports", program.imports.size()},
                      {"functions", program.functions.size()},
                      {"instructions", program.instructions.size()},
                      {"strings", program.strings.size()},
                      {"xrefs", program.xrefs.size()},
                      {"vtables", program.vtables.size()}};
    for (const auto& section : program.sections) {
        root["sections"].push_back({{"name", section.name},
                                    {"va", hex_addr(section.va)},
                                    {"size", section.virtual_size},
                                    {"file_offset", section.file_offset},
                                    {"executable", section.executable},
                                    {"writable", section.writable},
                                    {"entropy", section.entropy}});
    }
    for (const auto& imported : program.imports) {
        root["imports"].push_back({{"library", imported.library},
                                   {"name", imported.name},
                                   {"delayed", imported.delayed},
                                   {"ordinal", imported.ordinal}});
    }
    for (const auto& finding : program.findings) {
        root["findings"].push_back(
            {{"severity", finding.severity}, {"category", finding.category}, {"detail", finding.detail}});
    }
    for (const auto& function : program.functions) {
        root["functions"].push_back({{"name", function.name},
                                     {"address", hex_addr(function.address)},
                                     {"blocks", function.blocks.size()},
                                     {"calls", function.calls.size()}});
    }
    size_t shown = 0;
    for (const auto& item : program.strings) {
        if (shown == 2000) {
            break;
        }
        root["strings"].push_back(
            {{"address", hex_addr(item.address)}, {"utf16", item.utf16}, {"text", item.text}});
        ++shown;
    }
    for (const auto& table : program.vtables) {
        nlohmann::json slots = nlohmann::json::array();
        for (uint64_t slot : table.slots) {
            slots.push_back(hex_addr(slot));
        }
        root["vtables"].push_back({{"address", hex_addr(table.address)},
                                   {"name", table.name},
                                   {"source", table.source},
                                   {"slots", std::move(slots)}});
    }
    return root.dump(2) + "\n";
}

}  // namespace fathom
