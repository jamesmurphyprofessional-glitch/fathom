#include "fathom/engine.hpp"
#include "fathom/util.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace fathom {
namespace {

bool printable_ascii(unsigned char c) {
    return c >= 0x20 && c <= 0x7e;
}

bool excluded_pointer_section(std::string_view name) {
    std::string lower(name);
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    static constexpr const char* kSkip[] = {
        "got", "plt", "stub", "objc_sel", "objc_class", "cfstring", "la_symbol",
        "nl_symbol", "unwind", "eh_frame", "gcc_except",
    };
    for (const char* token : kSkip) {
        if (lower.find(token) != std::string::npos) {
            return true;
        }
    }
    return false;
}

uint64_t read_pointer(const uint8_t* data, int width) {
    uint64_t value = 0;
    for (int i = 0; i < width; ++i) {
        value |= static_cast<uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

bool points_at_exec(const Program& program, uint64_t address) {
    const Section* section = section_containing(program, address);
    return section != nullptr && section->executable;
}

struct Indicator {
    const char* name;
    const char* severity;
    const char* category;
    const char* detail;
};

const Indicator* find_indicator(std::string_view name) {
    static constexpr Indicator kTable[] = {
        {"CreateRemoteThread", "high", "process", "cross-process thread creation"},
        {"NtCreateThreadEx", "high", "process", "cross-process thread creation"},
        {"QueueUserAPC", "high", "process", "cross-process asynchronous procedure call"},
        {"WriteProcessMemory", "high", "process", "cross-process memory write"},
        {"NtWriteVirtualMemory", "high", "process", "cross-process memory write"},
        {"NtMapViewOfSection", "medium", "process", "section mapped into another process"},
        {"VirtualAllocEx", "medium", "process", "memory allocated in another process"},
        {"CreateProcessA", "low", "execution", "starts another program"},
        {"CreateProcessW", "low", "execution", "starts another program"},
        {"WinExec", "medium", "execution", "starts another program"},
        {"ShellExecuteA", "medium", "execution", "starts another program"},
        {"ShellExecuteW", "medium", "execution", "starts another program"},
        {"URLDownloadToFileA", "medium", "network", "downloads a file"},
        {"URLDownloadToFileW", "medium", "network", "downloads a file"},
        {"InternetOpenA", "info", "network", "network communication"},
        {"InternetOpenW", "info", "network", "network communication"},
        {"HttpSendRequestA", "info", "network", "network communication"},
        {"HttpSendRequestW", "info", "network", "network communication"},
        {"RegSetValueExA", "low", "persistence", "registry write"},
        {"RegSetValueExW", "low", "persistence", "registry write"},
        {"RegCreateKeyExA", "low", "persistence", "registry key creation"},
        {"RegCreateKeyExW", "low", "persistence", "registry key creation"},
        {"CreateServiceA", "medium", "persistence", "service creation"},
        {"CreateServiceW", "medium", "persistence", "service creation"},
        {"SetWindowsHookExA", "medium", "hook", "installs a Windows hook"},
        {"SetWindowsHookExW", "medium", "hook", "installs a Windows hook"},
        {"GetAsyncKeyState", "medium", "hook", "polls keyboard state"},
        {"MiniDumpWriteDump", "high", "dump", "process memory dump"},
        {"CredEnumerateA", "high", "credential", "credential store access"},
        {"CredEnumerateW", "high", "credential", "credential store access"},
        {"LsaRetrievePrivateData", "high", "credential", "LSA secret access"},
        {"IsDebuggerPresent", "low", "evasion", "debugger check"},
        {"CheckRemoteDebuggerPresent", "low", "evasion", "debugger check"},
        {"NtQueryInformationProcess", "low", "evasion", "process information query"},
        {"VirtualAlloc", "info", "loader", "memory allocation"},
        {"VirtualProtect", "info", "loader", "memory permission change"},
        {"LoadLibraryA", "info", "loader", "dynamic library load"},
        {"LoadLibraryW", "info", "loader", "dynamic library load"},
        {"GetProcAddress", "info", "loader", "dynamic export lookup"},
        {"task_for_pid", "high", "process", "Mach task port for another process"},
        {"mach_vm_write", "high", "process", "cross-task memory write"},
        {"mach_vm_allocate", "medium", "process", "cross-task allocation"},
        {"mach_vm_protect", "medium", "process", "cross-task permission change"},
        {"ptrace", "high", "process", "process trace control"},
        {"memfd_create", "medium", "loader", "anonymous executable memory file"},
        {"process_vm_writev", "high", "process", "cross-process memory write"},
    };
    std::string normalized(name);
    const auto bang = normalized.rfind('!');
    if (bang != std::string::npos) {
        normalized = normalized.substr(bang + 1);
    }
    const auto at = normalized.find('@');
    if (at != std::string::npos) {
        normalized = normalized.substr(0, at);
    }
    if (normalized.starts_with("_")) {
        normalized.erase(normalized.begin());
    }
    for (const auto& indicator : kTable) {
        if (normalized == indicator.name) {
            return &indicator;
        }
    }
    return nullptr;
}

void add_xref(Program& program, const Options& options, uint64_t from, uint64_t to, XrefKind kind) {
    if (program.xrefs.size() >= options.max_xrefs) {
        return;
    }
    program.xrefs.push_back(Xref{from, to, kind});
}

void scan_strings(Program& program, const Options& options) {
    program.strings.clear();
    const int min_len = std::max(options.min_string, 1);
    for (const auto& section : program.sections) {
        if (section.bytes.empty() || program.strings.size() >= options.max_strings) {
            continue;
        }
        const auto& bytes = section.bytes;
        size_t i = 0;
        while (i < bytes.size() && program.strings.size() < options.max_strings) {
            size_t j = i;
            while (j < bytes.size() && printable_ascii(bytes[j]) && (j - i) < 4096) {
                ++j;
            }
            if (static_cast<int>(j - i) >= min_len && (j == bytes.size() || !printable_ascii(bytes[j]))) {
                FoundString item;
                item.address = section.va + i;
                item.text.assign(reinterpret_cast<const char*>(bytes.data() + i), j - i);
                item.section = section.name;
                program.strings.push_back(std::move(item));
                i = j + (j < bytes.size() ? 1 : 0);
                continue;
            }
            if (i + 1 < bytes.size() && printable_ascii(bytes[i]) && bytes[i + 1] == 0) {
                size_t chars = 0;
                size_t k = i;
                while (k + 1 < bytes.size() && printable_ascii(bytes[k]) && bytes[k + 1] == 0 && chars < 4096) {
                    k += 2;
                    ++chars;
                }
                if (static_cast<int>(chars) >= min_len) {
                    FoundString item;
                    item.address = section.va + i;
                    item.utf16 = true;
                    item.section = section.name;
                    item.text.reserve(chars);
                    for (size_t n = 0; n < chars; ++n) {
                        item.text.push_back(static_cast<char>(bytes[i + n * 2]));
                    }
                    program.strings.push_back(std::move(item));
                    i = k;
                    continue;
                }
            }
            ++i;
        }
    }
    if (program.strings.size() >= options.max_strings) {
        program.notes.push_back("string cap reached (" + std::to_string(options.max_strings) + ")");
    }
}

void scan_pointers(Program& program, const Options& options) {
    const int width = program.address_size == 4 ? 4 : 8;
    for (const auto& section : program.sections) {
        if (section.executable || section.bytes.size() < static_cast<size_t>(width * 3)) {
            continue;
        }
        if (excluded_pointer_section(section.name)) {
            continue;
        }
        uint64_t run_at = 0;
        std::vector<uint64_t> slots;
        auto flush = [&]() {
            if (slots.size() >= 3) {
                VTable table;
                table.address = section.va + run_at;
                table.slots = slots;
                table.source = "pointer-scan";
                table.name = "vtable_" + hex_addr(table.address).substr(2);
                program.vtables.push_back(std::move(table));
            }
            slots.clear();
        };
        for (size_t i = 0; i + static_cast<size_t>(width) <= section.bytes.size(); i += static_cast<size_t>(width)) {
            const uint64_t value = read_pointer(section.bytes.data() + i, width);
            const uint64_t from = section.va + i;
            if (points_at_exec(program, value)) {
                if (slots.empty()) {
                    run_at = i;
                }
                slots.push_back(value);
                add_xref(program, options, from, value, XrefKind::Data);
            } else {
                flush();
            }
            if (program.xrefs.size() >= options.max_xrefs) {
                program.notes.push_back("cross-reference cap reached");
                flush();
                return;
            }
        }
        flush();
    }
    for (const auto& symbol : program.symbols) {
        if (symbol.name.find("_ZTV") == std::string::npos && symbol.name.find("??_7") == std::string::npos) {
            continue;
        }
        VTable table;
        table.address = symbol.address;
        table.name = symbol.display.empty() ? symbol.name : symbol.display;
        table.source = "symbol";
        const Section* section = section_containing(program, symbol.address);
        if (section != nullptr && symbol.address >= section->va) {
            const uint64_t offset = symbol.address - section->va;
            const int width_local = width;
            if (offset < section->bytes.size()) {
                for (size_t i = static_cast<size_t>(offset);
                     i + static_cast<size_t>(width_local) <= section->bytes.size() && table.slots.size() < 64;
                     i += static_cast<size_t>(width_local)) {
                    const uint64_t value = read_pointer(section->bytes.data() + i, width_local);
                    if (!points_at_exec(program, value)) {
                        break;
                    }
                    table.slots.push_back(value);
                }
            }
        }
        program.vtables.push_back(std::move(table));
    }
}

void scan_xrefs(Program& program, const Options& options) {
    program.xrefs.clear();
    for (const auto& insn : program.instructions) {
        if (program.xrefs.size() >= options.max_xrefs) {
            break;
        }
        if (insn.target && (insn.flow == Flow::Call || insn.flow == Flow::Jump || insn.flow == Flow::CondJump)) {
            const XrefKind kind = insn.flow == Flow::Call ? XrefKind::Call : XrefKind::Jump;
            add_xref(program, options, insn.address, *insn.target, kind);
        }
        for (uint64_t ref : insn.mem_refs) {
            add_xref(program, options, insn.address, ref, XrefKind::Data);
        }
    }
    scan_pointers(program, options);
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    ranges.reserve(program.strings.size());
    for (const auto& item : program.strings) {
        const auto end = checked_add(item.address, item.text.size() * (item.utf16 ? 2u : 1u));
        if (end) {
            ranges.emplace_back(item.address, *end);
        }
    }
    std::sort(ranges.begin(), ranges.end());
    for (auto& xref : program.xrefs) {
        if (xref.kind != XrefKind::Data) {
            continue;
        }
        auto it = std::upper_bound(ranges.begin(), ranges.end(), std::pair<uint64_t, uint64_t>{xref.to, UINT64_MAX});
        if (it == ranges.begin()) {
            continue;
        }
        --it;
        if (xref.to >= it->first && xref.to < it->second) {
            xref.kind = XrefKind::String;
        }
    }
}

void triage(Program& program) {
    program.findings.clear();
    for (const auto& section : program.sections) {
        if (section.executable && section.writable &&
            (section.virtual_size > 0 || !section.bytes.empty())) {
            program.findings.push_back(
                {"high", "memory", "writable and executable section " + section.name});
        }
        if (section.entropy >= 7.2 && section.bytes.size() >= 4096) {
            program.findings.push_back(
                {"medium", "packing", "high entropy (" + std::to_string(section.entropy) + ") in " + section.name});
        }
    }
    if (program.encrypted) {
        program.findings.push_back({"high", "packing", "Mach-O encryption flag is set"});
    }
    if (program.overlay_size > 0) {
        program.findings.push_back(
            {"info", "overlay", std::to_string(program.overlay_size) +
                                    " trailing bytes past the last section (signature or appended data)"});
    }
    bool exec = false;
    for (const auto& section : program.sections) {
        exec = exec || section.executable;
    }
    if (exec && program.imports.empty() && !program.relocatable) {
        program.findings.push_back(
            {"medium", "packing", "executable image has no imports"});
    }
    std::unordered_set<std::string> reported;
    for (const auto& imported : program.imports) {
        const Indicator* indicator = find_indicator(imported.name);
        if (indicator == nullptr || !reported.insert(indicator->name).second) {
            continue;
        }
        std::string detail = std::string(indicator->detail) + " (" + imported.name;
        if (!imported.library.empty()) {
            detail += " from " + imported.library;
        }
        detail += ")";
        program.findings.push_back({indicator->severity, indicator->category, std::move(detail)});
    }
}

}  // namespace

void analyze(Program& program, const Options& options) {
    for (auto& section : program.sections) {
        section.entropy = shannon_entropy(section.bytes.data(), section.bytes.size());
    }
    disassemble_program(program, options);
    scan_strings(program, options);
    scan_xrefs(program, options);
    triage(program);
}

}  // namespace fathom
