#include "fathom/engine.hpp"
#include "fathom/workbench.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace {

fathom::Program two_functions() {
    fathom::Program program;
    program.arch = fathom::Arch::X64;
    program.address_size = 8;
    program.image_base = 0x1000;
    program.entry = 0x1000;
    program.entry_known = true;
    program.format = fathom::Format::Elf;
    program.format_name = "ELF64";
    program.path = "/tmp/fathom-sample";
    std::vector<uint8_t> text(0x20, 0x90);
    text[0] = 0xc3;
    text[0x10] = 0xc3;
    fathom::Section code;
    code.name = ".text";
    code.va = 0x1000;
    code.virtual_size = text.size();
    code.executable = true;
    code.bytes = std::move(text);
    program.sections.push_back(std::move(code));
    program.symbols.push_back({"entry_fn", "entry_fn", 0x1000, true, false, false, ""});
    program.symbols.push_back({"helper", "helper", 0x1010, true, false, false, ""});
    fathom::Section data;
    data.name = ".rodata";
    data.va = 0x2000;
    const char marker[] = "HELLO_FATHOM";
    data.bytes.assign(marker, marker + sizeof marker);
    data.virtual_size = data.bytes.size();
    program.sections.push_back(std::move(data));
    fathom::analyze(program, {});
    program.xrefs.push_back({0x1000, 0x1010, fathom::XrefKind::Call});
    return program;
}

fathom::Program branched() {
    const uint8_t bytes[] = {
        0x48, 0x01, 0xfe, 0x48, 0x83, 0xfe, 0x00, 0x74, 0x05, 0x48, 0x89, 0xf0, 0xc3, 0x90, 0x48, 0x31, 0xc0, 0xc3,
    };
    fathom::Program program;
    program.arch = fathom::Arch::X64;
    program.address_size = 8;
    program.image_base = 0x1000;
    program.entry = 0x1000;
    program.entry_known = true;
    fathom::Section section;
    section.name = ".text";
    section.va = 0x1000;
    section.virtual_size = sizeof bytes;
    section.executable = true;
    section.bytes.assign(bytes, bytes + sizeof bytes);
    program.sections.push_back(std::move(section));
    fathom::disassemble_program(program, {});
    return program;
}

}  // namespace

TEST_CASE("a new workbench has nothing open") {
    fathom::Workbench bench;
    REQUIRE_FALSE(bench.has_program());
    REQUIRE_FALSE(bench.cursor_known());
    REQUIRE(bench.functions().empty());
    REQUIRE(bench.disassembly().empty());
    REQUIRE(bench.listing() == "no function to list\n");
    REQUIRE(bench.lower() == fathom::LowerView::Hex);
}

TEST_CASE("opening a program lands on the entry function") {
    fathom::Workbench bench;
    bench.set_program(two_functions());
    REQUIRE(bench.has_program());
    REQUIRE(bench.cursor_known());
    REQUIRE(bench.cursor() == 0x1000);
    REQUIRE(bench.arch_label() == "x86_64");
    REQUIRE(bench.format_label() == "ELF64");
    REQUIRE(bench.current_function() != nullptr);
    REQUIRE(bench.current_function()->name == "entry_fn");
    const auto rows = bench.disassembly();
    REQUIRE_FALSE(rows.empty());
    REQUIRE(rows.front().address == 0x1000);
    REQUIRE(rows.front().mnemonic == "ret");
    REQUIRE(bench.listing().find("structural listing") != std::string::npos);
    REQUIRE(bench.listing().find("not Hex-Rays") != std::string::npos);
    REQUIRE(bench.listing().find("entry_fn") != std::string::npos);
}

TEST_CASE("the sidebar filter matches function and string names") {
    fathom::Workbench bench;
    bench.set_program(two_functions());
    bench.set_filter("HELP");
    const auto functions = bench.functions();
    REQUIRE(functions.size() == 1);
    REQUIRE(functions[0].name == "helper");
    REQUIRE(functions[0].address == 0x1010);
    const auto strings = bench.strings();
    REQUIRE(strings.empty());
    bench.set_filter("hello");
    REQUIRE(bench.functions().empty());
    REQUIRE(bench.strings().size() == 1);
    REQUIRE(bench.strings()[0].address == 0x2000);
    REQUIRE(bench.strings()[0].text == "HELLO_FATHOM");
}

TEST_CASE("selecting an address moves the cursor and the views") {
    fathom::Workbench bench;
    bench.set_program(two_functions());
    bench.select(0x1010);
    REQUIRE(bench.cursor() == 0x1010);
    REQUIRE(bench.current_function()->name == "helper");
    REQUIRE(bench.disassembly().front().address == 0x1010);
    REQUIRE(bench.listing().find("helper") != std::string::npos);
    const auto xrefs = bench.xrefs();
    REQUIRE(xrefs.size() == 1);
    REQUIRE(xrefs[0].from == 0x1000);
    REQUIRE(xrefs[0].kind == "call");

    bench.select(0x2000);
    REQUIRE(bench.cursor() == 0x2000);
    REQUIRE(bench.current_function() == nullptr);
    REQUIRE(bench.disassembly().empty());
    REQUIRE(bench.listing() == "no function to list\n");
    const auto hex = bench.hex();
    bool saw = false;
    for (const auto& line : hex) {
        for (const auto& cell : line.cells) {
            if (cell.present && cell.address == 0x2000 && cell.value == 'H') {
                saw = true;
            }
        }
    }
    REQUIRE(saw);
}

TEST_CASE("the graph follows the recovered blocks") {
    fathom::Workbench bench;
    bench.set_program(branched());
    bench.select(0x1007);
    REQUIRE(bench.current_function() != nullptr);
    const auto rows = bench.disassembly();
    bool saw_branch = false;
    for (const auto& row : rows) {
        if (row.address == 0x1007) {
            saw_branch = row.jump;
        }
    }
    REQUIRE(saw_branch);
    const auto blocks = bench.graph();
    REQUIRE(blocks.size() == 3);
    bool edge = false;
    for (const auto& block : blocks) {
        for (uint64_t succ : block.succs) {
            if (succ == 0x100e) {
                edge = true;
            }
        }
    }
    REQUIRE(edge);
    bench.set_lower(fathom::LowerView::Graph);
    REQUIRE(bench.lower() == fathom::LowerView::Graph);
}
