#include "fathom/engine.hpp"
#include "fathom/util.hpp"

#include <llvm/BinaryFormat/COFF.h>
#include <llvm/BinaryFormat/ELF.h>
#include <llvm/BinaryFormat/MachO.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/MachO.h>
#include <llvm/Object/MachOUniversal.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/TargetParser/Triple.h>

#include <fmt/format.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <unordered_set>

namespace fathom {
namespace {

std::string demangle_symbol(std::string_view name) {
    std::string_view mangled = name;
    if (mangled.starts_with("__Z") || mangled.starts_with("__R")) {
        mangled.remove_prefix(1);
    }
    if (mangled.starts_with("_R")) {
        if (char* text = llvm::rustDemangle(mangled)) {
            std::string out(text);
            std::free(text);
            return out;
        }
    }
    if (mangled.starts_with("_Z")) {
        if (char* text = llvm::itaniumDemangle(mangled)) {
            std::string out(text);
            std::free(text);
            return out;
        }
    }
    if (!name.empty() && name.front() == '?') {
        int status = 0;
        if (char* text = llvm::microsoftDemangle(name, nullptr, &status)) {
            std::string out(text);
            std::free(text);
            return out;
        }
    }
    return std::string(name);
}

std::string fixed16(const char* text) {
    size_t n = 0;
    while (n < 16 && text[n] != '\0') {
        ++n;
    }
    return std::string(text, n);
}

std::string load_command_string(const llvm::object::MachOObjectFile::LoadCommandInfo& command,
                                uint32_t offset) {
    if (offset >= command.C.cmdsize) {
        return {};
    }
    const char* start = command.Ptr + offset;
    const size_t max_len = static_cast<size_t>(command.C.cmdsize - offset);
    size_t n = 0;
    while (n < max_len && start[n] != '\0') {
        ++n;
    }
    return std::string(start, n);
}

std::string format_uuid(const uint8_t* bytes) {
    return fmt::format(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

Arch arch_from_triple(llvm::Triple::ArchType arch) {
    switch (arch) {
    case llvm::Triple::x86:
        return Arch::X86;
    case llvm::Triple::x86_64:
        return Arch::X64;
    case llvm::Triple::arm:
    case llvm::Triple::thumb:
        return Arch::Arm;
    case llvm::Triple::aarch64:
    case llvm::Triple::aarch64_be:
    case llvm::Triple::aarch64_32:
        return Arch::Arm64;
    default:
        return Arch::Unknown;
    }
}

void keep_note(Program& program, llvm::Error error) {
    if (error) {
        program.notes.push_back(llvm::toString(std::move(error)));
    }
}

struct SegmentInfo {
    std::string name;
    uint64_t vmaddr = 0;
    uint64_t vmsize = 0;
    uint64_t fileoff = 0;
    uint64_t filesize = 0;
    uint32_t initprot = 0;
};

std::vector<SegmentInfo> macho_segments(const llvm::object::MachOObjectFile& macho) {
    std::vector<SegmentInfo> segments;
    for (const auto& command : macho.load_commands()) {
        SegmentInfo segment;
        if (command.C.cmd == llvm::MachO::LC_SEGMENT_64) {
            const auto raw = macho.getSegment64LoadCommand(command);
            segment.name = fixed16(raw.segname);
            segment.vmaddr = raw.vmaddr;
            segment.vmsize = raw.vmsize;
            segment.fileoff = raw.fileoff;
            segment.filesize = raw.filesize;
            segment.initprot = raw.initprot;
            segments.push_back(segment);
        } else if (command.C.cmd == llvm::MachO::LC_SEGMENT) {
            const auto raw = macho.getSegmentLoadCommand(command);
            segment.name = fixed16(raw.segname);
            segment.vmaddr = raw.vmaddr;
            segment.vmsize = raw.vmsize;
            segment.fileoff = raw.fileoff;
            segment.filesize = raw.filesize;
            segment.initprot = raw.initprot;
            segments.push_back(segment);
        }
    }
    return segments;
}

const SegmentInfo* find_segment(const std::vector<SegmentInfo>& segments, const std::string& name) {
    for (const auto& segment : segments) {
        if (segment.name == name) {
            return &segment;
        }
    }
    return nullptr;
}

void read_macho_commands(const llvm::object::MachOObjectFile& macho,
                         const std::vector<SegmentInfo>& segments, Program& program) {
    for (const auto& command : macho.load_commands()) {
        const uint32_t cmd = command.C.cmd;
        if (cmd == llvm::MachO::LC_LOAD_DYLIB || cmd == llvm::MachO::LC_LOAD_WEAK_DYLIB ||
            cmd == llvm::MachO::LC_REEXPORT_DYLIB || cmd == llvm::MachO::LC_LOAD_UPWARD_DYLIB ||
            cmd == llvm::MachO::LC_LAZY_LOAD_DYLIB) {
            const auto dylib = macho.getDylibIDLoadCommand(command);
            const std::string name = load_command_string(command, dylib.dylib.name);
            if (!name.empty()) {
                program.libraries.push_back(name);
            }
        } else if (cmd == llvm::MachO::LC_ENCRYPTION_INFO_64) {
            if (macho.getEncryptionInfoCommand64(command).cryptid != 0) {
                program.encrypted = true;
            }
        } else if (cmd == llvm::MachO::LC_ENCRYPTION_INFO) {
            if (macho.getEncryptionInfoCommand(command).cryptid != 0) {
                program.encrypted = true;
            }
        } else if (cmd == llvm::MachO::LC_MAIN && !program.relocatable) {
            const auto entry = macho.getEntryPointCommand(command);
            for (const auto& segment : segments) {
                if (segment.filesize == 0 || entry.entryoff < segment.fileoff) {
                    continue;
                }
                const uint64_t delta = entry.entryoff - segment.fileoff;
                if (delta >= segment.filesize) {
                    continue;
                }
                if (const auto va = checked_add(segment.vmaddr, delta)) {
                    program.entry = *va;
                    program.entry_known = true;
                    break;
                }
            }
        }
    }

    if (!program.relocatable) {
        for (const auto& segment : segments) {
            if (segment.filesize == 0) {
                continue;
            }
            if (program.image_base == 0 || segment.vmaddr < program.image_base) {
                program.image_base = segment.vmaddr;
            }
        }
    }

    const auto uuid = macho.getUuid();
    if (uuid.size() == 16) {
        program.uuid = format_uuid(uuid.data());
    }
    for (uint64_t start : macho.getFunctionStarts()) {
        if (start != 0) {
            program.function_starts.push_back(start);
        }
    }
}

void read_coff_tables(llvm::object::COFFObjectFile& coff, Program& program) {
    program.image_base = coff.getImageBase();
    for (const auto& directory : coff.import_directories()) {
        llvm::StringRef library;
        if (llvm::Error error = directory.getName(library)) {
            keep_note(program, std::move(error));
            continue;
        }
        for (const auto& imported : directory.imported_symbols()) {
            Import item;
            item.library = library.str();
            bool ordinal = false;
            if (llvm::Error error = imported.isOrdinal(ordinal)) {
                keep_note(program, std::move(error));
                continue;
            }
            if (ordinal) {
                uint16_t ordinal_value = 0;
                if (llvm::Error error = imported.getOrdinal(ordinal_value)) {
                    keep_note(program, std::move(error));
                    continue;
                }
                item.ordinal = true;
                item.ordinal_value = ordinal_value;
                item.name = "#" + std::to_string(ordinal_value);
            } else {
                llvm::StringRef name;
                if (llvm::Error error = imported.getSymbolName(name)) {
                    keep_note(program, std::move(error));
                    continue;
                }
                item.name = name.str();
            }
            if (!item.name.empty()) {
                program.imports.push_back(std::move(item));
            }
        }
    }
    for (const auto& directory : coff.delay_import_directories()) {
        llvm::StringRef library;
        if (llvm::Error error = directory.getName(library)) {
            keep_note(program, std::move(error));
            continue;
        }
        for (const auto& imported : directory.imported_symbols()) {
            llvm::StringRef name;
            if (llvm::Error error = imported.getSymbolName(name)) {
                keep_note(program, std::move(error));
                continue;
            }
            Import item;
            item.library = library.str();
            item.name = name.str();
            item.delayed = true;
            if (!item.name.empty()) {
                program.imports.push_back(std::move(item));
            }
        }
    }
    for (const auto& exported : coff.export_directories()) {
        llvm::StringRef name;
        uint32_t rva = 0;
        if (llvm::Error error = exported.getSymbolName(name)) {
            keep_note(program, std::move(error));
            continue;
        }
        if (llvm::Error error = exported.getExportRVA(rva)) {
            keep_note(program, std::move(error));
            continue;
        }
        Symbol symbol;
        symbol.name = name.str();
        symbol.display = demangle_symbol(symbol.name);
        symbol.exported = true;
        symbol.function = true;
        if (const auto address = checked_add(program.image_base, rva)) {
            symbol.address = *address;
        }
        program.exports.push_back(std::move(symbol));
    }
}

void add_symbol(llvm::object::ObjectFile& object, const llvm::object::SymbolRef& symbol_ref,
                Program& program, bool from_coff_imports) {
    auto name_or = symbol_ref.getName();
    if (!name_or) {
        keep_note(program, name_or.takeError());
        return;
    }
    Symbol symbol;
    symbol.name = name_or->str();
    if (symbol.name.empty()) {
        return;
    }
    auto flags_or = symbol_ref.getFlags();
    if (!flags_or) {
        keep_note(program, flags_or.takeError());
        return;
    }
    const uint32_t flags = *flags_or;
    symbol.imported = (flags & llvm::object::SymbolRef::SF_Undefined) != 0;
    symbol.exported = !symbol.imported && ((flags & llvm::object::SymbolRef::SF_Exported) != 0 ||
                                           (flags & llvm::object::SymbolRef::SF_Global) != 0);
    auto type_or = symbol_ref.getType();
    if (!type_or) {
        keep_note(program, type_or.takeError());
        return;
    }
    symbol.function = *type_or == llvm::object::SymbolRef::ST_Function;

    if (!symbol.imported) {
        if (program.relocatable) {
            auto value_or = symbol_ref.getValue();
            auto section_or = symbol_ref.getSection();
            if (!value_or || !section_or) {
                if (!value_or) {
                    keep_note(program, value_or.takeError());
                }
                if (!section_or) {
                    keep_note(program, section_or.takeError());
                }
                return;
            }
            if (*section_or != object.section_end()) {
                const uint64_t index = (*section_or)->getIndex();
                for (const auto& section : program.sections) {
                    if (section.index == index) {
                        if (const auto address = checked_add(section.va, *value_or)) {
                            symbol.address = *address;
                        }
                        break;
                    }
                }
            }
        } else {
            auto address_or = symbol_ref.getAddress();
            if (!address_or) {
                keep_note(program, address_or.takeError());
                return;
            }
            symbol.address = *address_or;
        }
    }

    symbol.display = demangle_symbol(symbol.name);
    if (symbol.exported) {
        program.exports.push_back(symbol);
    }
    if (symbol.imported && !from_coff_imports) {
        Import imported;
        imported.name = symbol.name;
        program.imports.push_back(std::move(imported));
    }
    program.symbols.push_back(std::move(symbol));
}

void fill_program(llvm::object::ObjectFile& object, Program& program) {
    program.format_name = object.getFileFormatName().str();
    program.arch = arch_from_triple(object.getArch());
    program.address_size = object.getBytesInAddress() == 4 ? 4 : 8;
    program.relocatable = object.isRelocatableObject();
    auto* macho = llvm::dyn_cast<llvm::object::MachOObjectFile>(&object);
    auto* coff = llvm::dyn_cast<llvm::object::COFFObjectFile>(&object);
    if (macho) {
        program.format = Format::MachO;
    } else if (coff) {
        program.format = (coff->getPE32Header() || coff->getPE32PlusHeader()) ? Format::Pe : Format::Coff;
    } else if (object.isELF()) {
        program.format = Format::Elf;
    }

    std::vector<SegmentInfo> segments;
    if (macho) {
        segments = macho_segments(*macho);
    }

    for (const llvm::object::SectionRef& section_ref : object.sections()) {
        Section section;
        section.index = section_ref.getIndex();
        auto name_or = section_ref.getName();
        if (!name_or) {
            keep_note(program, name_or.takeError());
            section.name = "section_" + std::to_string(section.index);
        } else {
            section.name = name_or->str();
        }
        section.va = section_ref.getAddress();
        section.virtual_size = section_ref.getSize();
        section.executable = section_ref.isText();
        const bool bss = section_ref.isBSS() || section_ref.isVirtual();
        if (!bss) {
            auto contents = section_ref.getContents();
            if (!contents) {
                keep_note(program, contents.takeError());
            } else {
                section.bytes.assign(contents->begin(), contents->end());
            }
        }
        if (macho) {
            std::string segment_name;
            if (macho->is64Bit()) {
                const auto raw = macho->getSection64(section_ref.getRawDataRefImpl());
                section.file_offset = raw.offset;
                segment_name = fixed16(raw.segname);
            } else {
                const auto raw = macho->getSection(section_ref.getRawDataRefImpl());
                section.file_offset = raw.offset;
                segment_name = fixed16(raw.segname);
            }
            if (const SegmentInfo* segment = find_segment(segments, segment_name)) {
                section.writable = (segment->initprot & llvm::MachO::VM_PROT_WRITE) != 0;
                section.readable = (segment->initprot & llvm::MachO::VM_PROT_READ) != 0;
                if ((segment->initprot & llvm::MachO::VM_PROT_EXECUTE) != 0) {
                    section.executable = true;
                }
            }
        } else if (object.isELF()) {
            const llvm::object::ELFSectionRef elf_section(section_ref);
            const uint64_t flags = elf_section.getFlags();
            section.file_offset = elf_section.getOffset();
            section.writable = (flags & llvm::ELF::SHF_WRITE) != 0;
            if ((flags & llvm::ELF::SHF_EXECINSTR) != 0) {
                section.executable = true;
            }
        } else if (coff) {
            const llvm::object::coff_section* raw = coff->getCOFFSection(section_ref);
            const uint32_t flags = raw->Characteristics;
            section.file_offset = raw->PointerToRawData;
            section.writable = (flags & llvm::COFF::IMAGE_SCN_MEM_WRITE) != 0;
            section.readable = (flags & llvm::COFF::IMAGE_SCN_MEM_READ) != 0;
            if ((flags & llvm::COFF::IMAGE_SCN_MEM_EXECUTE) != 0) {
                section.executable = true;
            }
        }
        program.sections.push_back(std::move(section));
    }

    if (program.relocatable) {
        uint64_t cursor = 0x10000;
        for (auto& section : program.sections) {
            section.va = cursor;
            const uint64_t span = std::max(section.virtual_size, static_cast<uint64_t>(section.bytes.size()));
            const uint64_t step = (span + 15ull) & ~15ull;
            const auto next = checked_add(cursor, step == 0 ? 16 : step);
            if (!next) {
                throw Error("relocatable image layout overflowed");
            }
            cursor = *next;
        }
        program.image_base = program.sections.empty() ? 0 : program.sections.front().va;
    }

    auto start = object.getStartAddress();
    if (start) {
        program.entry = *start;
        program.entry_known = program.entry != 0 || !program.relocatable;
    } else {
        keep_note(program, start.takeError());
    }

    if (macho) {
        read_macho_commands(*macho, segments, program);
    }
    if (coff && program.format == Format::Pe) {
        read_coff_tables(*coff, program);
    }

    const bool coff_imports = coff && program.format == Format::Pe;
    std::unordered_set<std::string> seen;
    auto consider = [&](const llvm::object::SymbolRef& symbol_ref) {
        const size_t before = program.symbols.size();
        add_symbol(object, symbol_ref, program, coff_imports);
        if (program.symbols.size() == before) {
            return;
        }
        const Symbol& added = program.symbols.back();
        const std::string key = added.name + "\n" + std::to_string(added.address) + (added.imported ? "i" : "d");
        if (!seen.insert(key).second) {
            if (added.imported && !program.imports.empty() && program.imports.back().name == added.name) {
                program.imports.pop_back();
            }
            if (added.exported && !program.exports.empty() && program.exports.back().name == added.name &&
                program.exports.back().address == added.address) {
                program.exports.pop_back();
            }
            program.symbols.pop_back();
        }
    };
    for (const llvm::object::SymbolRef& symbol_ref : object.symbols()) {
        consider(symbol_ref);
    }
    auto consider_dynamic = [&](const auto& elf) {
        for (auto it = elf.dynamic_symbol_begin(); it != elf.dynamic_symbol_end(); ++it) {
            consider(llvm::object::SymbolRef(*it));
        }
    };
    if (const auto* elf = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(&object)) {
        consider_dynamic(*elf);
    } else if (const auto* elf = llvm::dyn_cast<llvm::object::ELF64BEObjectFile>(&object)) {
        consider_dynamic(*elf);
    } else if (const auto* elf = llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(&object)) {
        consider_dynamic(*elf);
    } else if (const auto* elf = llvm::dyn_cast<llvm::object::ELF32BEObjectFile>(&object)) {
        consider_dynamic(*elf);
    }

    uint64_t high = program.image_base;
    uint64_t covered = 0;
    for (const auto& section : program.sections) {
        const uint64_t span = std::max(section.virtual_size, static_cast<uint64_t>(section.bytes.size()));
        if (const auto end = checked_add(section.va, span)) {
            high = std::max(high, *end);
        }
        if (!section.bytes.empty()) {
            if (const auto end = checked_add(section.file_offset, static_cast<uint64_t>(section.bytes.size()))) {
                covered = std::max(covered, *end);
            }
        }
    }
    if (high >= program.image_base) {
        program.image_size = high - program.image_base;
    }
    if (program.file_size > covered + 512) {
        program.overlay_size = program.file_size - covered;
    }
}

std::unique_ptr<llvm::object::ObjectFile> open_object(llvm::MemoryBufferRef ref, const Options& options,
                                                      Program& program) {
    auto object_or = llvm::object::ObjectFile::createObjectFile(ref);
    if (object_or) {
        return std::move(*object_or);
    }
    llvm::Error object_error = object_or.takeError();
    auto fat_or = llvm::object::MachOUniversalBinary::create(ref);
    if (!fat_or) {
        throw Error(llvm::toString(std::move(object_error)) + "; " + llvm::toString(fat_or.takeError()));
    }
    llvm::consumeError(std::move(object_error));

    struct Candidate {
        std::string name;
        std::unique_ptr<llvm::object::MachOObjectFile> object;
    };
    std::vector<Candidate> candidates;
    for (const auto& slice : (*fat_or)->objects()) {
        auto slice_object = slice.getAsObjectFile();
        if (!slice_object) {
            keep_note(program, slice_object.takeError());
            continue;
        }
        candidates.push_back(Candidate{slice.getArchFlagName(), std::move(*slice_object)});
    }
    if (candidates.empty()) {
        throw Error("universal Mach-O contained no loadable slices");
    }
    std::string available;
    for (const auto& candidate : candidates) {
        if (!available.empty()) {
            available += ", ";
        }
        available += candidate.name.empty() ? "?" : candidate.name;
    }
    program.notes.push_back("universal slices: " + available);

    Candidate* pick = nullptr;
    if (!options.slice.empty()) {
        for (auto& candidate : candidates) {
            if (iequals(candidate.name, options.slice)) {
                pick = &candidate;
                break;
            }
        }
        if (pick == nullptr) {
            throw Error("slice '" + options.slice + "' is not in this universal binary (" + available + ")");
        }
    } else {
        for (const char* preferred : {"arm64", "x86_64", "arm64e"}) {
            for (auto& candidate : candidates) {
                if (iequals(candidate.name, preferred)) {
                    pick = &candidate;
                    break;
                }
            }
            if (pick != nullptr) {
                break;
            }
        }
        if (pick == nullptr) {
            pick = &candidates.front();
        }
    }
    program.slice = pick->name;
    return std::move(pick->object);
}

}  // namespace

Program load_program(const std::string& path, const Options& options) {
    namespace fs = std::filesystem;
    std::error_code exists_error;
    const fs::path file(path);
    if (!fs::is_regular_file(file, exists_error)) {
        throw Error("not a regular file: " + path);
    }
    const auto file_size = fs::file_size(file, exists_error);
    if (exists_error) {
        throw Error("cannot size " + path + ": " + exists_error.message());
    }
    if (file_size > options.max_file_bytes) {
        throw Error("file is " + std::to_string(file_size) + " bytes; the cap is " +
                    std::to_string(options.max_file_bytes) + " (raise it with --max-bytes)");
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw Error("cannot open " + path);
    }
    Program program;
    program.path = path;
    program.file_size = static_cast<uint64_t>(file_size);
    program.file_bytes.resize(static_cast<size_t>(file_size));
    if (file_size != 0) {
        input.read(reinterpret_cast<char*>(program.file_bytes.data()), static_cast<std::streamsize>(file_size));
        if (input.gcount() != static_cast<std::streamsize>(file_size)) {
            throw Error("short read of " + path);
        }
    }

    auto buffer = llvm::MemoryBuffer::getMemBuffer(
        llvm::StringRef(reinterpret_cast<const char*>(program.file_bytes.data()), program.file_bytes.size()), path,
        false);
    auto object = open_object(buffer->getMemBufferRef(), options, program);
    fill_program(*object, program);
    return program;
}

}  // namespace fathom
