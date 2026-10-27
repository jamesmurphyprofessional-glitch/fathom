#include "fathom/debug.hpp"
#include "fathom/engine.hpp"
#include "fathom/retsync.hpp"
#include "fathom/util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

extern char** environ;

namespace {

namespace fs = std::filesystem;

std::string source_path(const std::string& name) {
    return std::string(FATHOM_SOURCE_DIR) + "/tests/" + name;
}

std::string fixture_path(const std::string& name) {
    return std::string(FATHOM_FIXTURE_DIR) + "/" + name;
}

bool run_process(const std::vector<std::string>& args) {
    if (args.empty()) {
        return false;
    }
    std::vector<std::string> owned = args;
    std::vector<char*> argv;
    for (auto& arg : owned) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);
    pid_t pid = 0;
    const int rc = posix_spawn(&pid, owned.front().c_str(), nullptr, nullptr, argv.data(), environ);
    if (rc != 0) {
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool fresh(const std::string& output, const std::string& source) {
    std::error_code error;
    if (!fs::is_regular_file(output, error)) {
        return false;
    }
    const auto out_time = fs::last_write_time(output, error);
    if (error) {
        return false;
    }
    const auto src_time = fs::last_write_time(source, error);
    if (error) {
        return false;
    }
    return out_time >= src_time;
}

std::string ensure_built(const std::string& output, const std::vector<std::string>& args, const std::string& source) {
    if (fresh(output, source)) {
        return output;
    }
    fs::create_directories(FATHOM_FIXTURE_DIR);
    if (!run_process(args) || !fs::is_regular_file(output)) {
        return {};
    }
    return output;
}

void write_bytes(const fs::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    REQUIRE(output.good());
}

fathom::Program code_program(fathom::Arch arch, uint64_t address, std::vector<uint8_t> bytes) {
    fathom::Program program;
    program.arch = arch;
    program.address_size = arch == fathom::Arch::X86 ? 4 : 8;
    program.image_base = address;
    program.entry = address;
    program.entry_known = true;
    fathom::Section section;
    section.name = ".text";
    section.va = address;
    section.virtual_size = bytes.size();
    section.executable = true;
    section.bytes = std::move(bytes);
    program.sections.push_back(std::move(section));
    return program;
}

void send_all(int fd, const std::string& bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
        const ssize_t n = ::send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        REQUIRE(n > 0);
        sent += static_cast<size_t>(n);
    }
}

}  // namespace

TEST_CASE("entropy of a constant buffer is zero") {
    const uint8_t bytes[32] = {};
    REQUIRE(fathom::shannon_entropy(bytes, sizeof bytes) == 0);
    REQUIRE(fathom::shannon_entropy(nullptr, 4) == 0);
    const uint8_t mixed[] = {0, 1, 2, 3, 4, 5, 6, 7};
    REQUIRE(fathom::shannon_entropy(mixed, sizeof mixed) > 2.0);
}

TEST_CASE("rsp checksum and stop framing") {
    REQUIRE(fathom::rsp_checksum("OK") == "9a");
    REQUIRE(fathom::rsp_checksum("") == "00");
    const std::string wire = "$T05thread:1;medata:11;#00$OK#9a";
    const auto first = fathom::rsp_take_frame(wire);
    REQUIRE(first.has_value());
    REQUIRE(first->payload.starts_with("T05"));
    REQUIRE_FALSE(first->checksum_match);
    const auto second = fathom::rsp_take_frame(std::string_view(wire).substr(first->consumed));
    REQUIRE(second.has_value());
    REQUIRE(second->payload == "OK");
    REQUIRE(second->checksum_match);
    REQUIRE_FALSE(fathom::rsp_take_frame("$OK#9").has_value());
}

TEST_CASE("synthetic x64 control flow has three blocks") {
    const uint8_t bytes[] = {
        0x48, 0x01, 0xfe, 0x48, 0x83, 0xfe, 0x00, 0x74, 0x05, 0x48, 0x89, 0xf0, 0xc3, 0x90, 0x48, 0x31, 0xc0, 0xc3,
    };
    fathom::Program program = code_program(fathom::Arch::X64, 0x1000, {bytes, bytes + sizeof bytes});
    fathom::disassemble_program(program, {});
    REQUIRE(program.functions.size() == 1);
    REQUIRE(program.functions[0].blocks.size() == 3);
    const fathom::Instruction* branch = fathom::find_insn(program, 0x1007);
    REQUIRE(branch != nullptr);
    REQUIRE(branch->flow == fathom::Flow::CondJump);
    REQUIRE(branch->target.has_value());
    REQUIRE(*branch->target == 0x100e);
}

TEST_CASE("arm64 add and ret decode") {
    const uint8_t bytes[] = {0x00, 0x01, 0x00, 0x0b, 0xc0, 0x03, 0x5f, 0xd6};
    fathom::Program program = code_program(fathom::Arch::Arm64, 0x1000, {bytes, bytes + sizeof bytes});
    fathom::disassemble_program(program, {});
    REQUIRE(program.instructions.size() == 2);
    REQUIRE(program.instructions[0].mnemonic == "add");
    REQUIRE(program.instructions[1].mnemonic == "ret");
}

TEST_CASE("import names become capability findings") {
    fathom::Program program;
    program.imports.push_back(fathom::Import{"KERNEL32.dll", "CreateRemoteThread", false, false, 0});
    fathom::Section section;
    section.name = ".text";
    section.executable = true;
    section.writable = true;
    section.virtual_size = 16;
    section.bytes = {0xc3};
    program.sections.push_back(section);
    fathom::analyze(program, {});
    bool saw_import = false;
    bool saw_wx = false;
    for (const auto& finding : program.findings) {
        if (finding.detail.find("CreateRemoteThread") != std::string::npos && finding.severity == "high") {
            saw_import = true;
        }
        if (finding.category == "memory") {
            saw_wx = true;
        }
    }
    REQUIRE(saw_import);
    REQUIRE(saw_wx);
}

TEST_CASE("aligned executable pointers become a vtable") {
    fathom::Program program = code_program(fathom::Arch::Arm64, 0x1000, {0xc0, 0x03, 0x5f, 0xd6});
    fathom::Section data;
    data.name = "__const";
    data.va = 0x2000;
    data.virtual_size = 24;
    const uint8_t pointer[] = {0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    for (int i = 0; i < 3; ++i) {
        data.bytes.insert(data.bytes.end(), pointer, pointer + sizeof pointer);
    }
    program.sections.push_back(std::move(data));
    fathom::analyze(program, {});
    REQUIRE_FALSE(program.vtables.empty());
    REQUIRE(program.vtables[0].slots.size() >= 3);
}

TEST_CASE("ascii and utf16 strings are recovered from section bytes") {
    fathom::Program program;
    program.address_size = 8;
    fathom::Section section;
    section.name = ".rdata";
    section.va = 0x4000;
    const char marker[] = "FATHOM_MARKER_STRING";
    section.bytes.assign(marker, marker + sizeof marker);
    const unsigned short wide[] = {'F', 'A', 'T', 'H', 'O', 'M', 'W', 'I', 'D', 'E', 0};
    for (unsigned short unit : wide) {
        section.bytes.push_back(static_cast<uint8_t>(unit & 0xff));
        section.bytes.push_back(static_cast<uint8_t>((unit >> 8) & 0xff));
    }
    section.virtual_size = section.bytes.size();
    program.sections.push_back(std::move(section));
    fathom::analyze(program, {});
    bool ascii = false;
    bool utf16 = false;
    for (const auto& text : program.strings) {
        if (text.text.find("FATHOM_MARKER_STRING") != std::string::npos) {
            ascii = true;
        }
        if (text.utf16 && text.text.find("FATHOMWIDE") != std::string::npos) {
            utf16 = true;
        }
    }
    REQUIRE(ascii);
    REQUIRE(utf16);
}

TEST_CASE("hex dump rejects an offset past the file") {
    fathom::Program program;
    program.file_bytes = {1, 2, 3, 4};
    const std::string text = fathom::render_hex(program, 100, false, 16);
    REQUIRE(text.find("past the end") != std::string::npos);
    const std::string empty = fathom::render_hex(program, 0, true, 16);
    REQUIRE(empty.find("not in a file-backed section") != std::string::npos);
}

TEST_CASE("oversized files and random bytes are refused cleanly") {
    const fs::path dir(FATHOM_FIXTURE_DIR);
    fs::create_directories(dir);
    const fs::path big = dir / "too-big.bin";
    write_bytes(big, std::vector<uint8_t>(64, 0x41));
    fathom::Options options;
    options.max_file_bytes = 16;
    REQUIRE_THROWS_AS(fathom::load_program(big.string(), options), fathom::Error);

    const fs::path junk = dir / "random.bin";
    std::vector<uint8_t> bytes(64);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(i * 17 + 3);
    }
    write_bytes(junk, bytes);
    REQUIRE_THROWS_AS(fathom::load_program(junk.string()), fathom::Error);
}

TEST_CASE("rebase and the loopback ret-sync listener") {
    constexpr uint64_t kBase = 0x100000000ull;
    constexpr uint64_t kRuntime = 0x200000000ull;
    REQUIRE(fathom::rebase_to_static(kBase, kRuntime, kRuntime + 0x123) == kBase + 0x123);

    fathom::Program program;
    program.image_base = kBase;
    program.path = "/tmp/libspin\nplatform shell whoami";
    fathom::RetSyncServer server(program);
    server.start("127.0.0.1", 0, false);
    REQUIRE(server.port() != 0);

    fathom::RetSyncServer refused(program);
    REQUIRE_THROWS_AS(refused.start("0.0.0.0", 0, false), fathom::Error);

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(server.port());
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0);

    std::string hello = "hello";
    send_all(fd,
             "[notice]{\"type\":\"new_dbg\",\"msg\":\"test\",\"dialect\":\"lldb\"}\n"
             "[notice]{\"type\":\"module\",\"path\":\"/tmp/libspin\\nplatform shell whoami\"}\n"
             "[sync]{\"type\":\"loc\",\"base\":8589934592,\"offset\":8589934883}\n"
             "[sync]{\"type\":\"cmd\",\"msg\":\"aGVsbG8=\",\"base\":8589934592,\"offset\":8589934883}\n"
             "[notice]{\"type\":\"idb_list\"}\n"
             "rm -rf /\n");

    REQUIRE(server.wait_location(std::chrono::seconds(2)));
    const fathom::SyncState state = server.state();
    REQUIRE(state.dialect == "lldb");
    REQUIRE(state.connected);
    REQUIRE(state.static_va == kBase + 0x123);
    REQUIRE(state.runtime_pc == kRuntime + 0x123);

    bool saw_hello = false;
    for (int i = 0; i < 50 && !saw_hello; ++i) {
        for (const auto& comment : server.state().comments) {
            if (comment.text == hello && comment.source == "ret-sync-output") {
                saw_hello = true;
            }
        }
        if (!saw_hello) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    REQUIRE(saw_hello);
    bool ignored = false;
    for (int i = 0; i < 50 && !ignored; ++i) {
        if (server.state().last_error.find("ignored") != std::string::npos) {
            ignored = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    REQUIRE(ignored);

    std::string reply;
    for (int i = 0; i < 50 && reply.find("libspin") == std::string::npos; ++i) {
        pollfd wait_fd {};
        wait_fd.fd = fd;
        wait_fd.events = POLLIN;
        if (::poll(&wait_fd, 1, 20) > 0) {
            char buffer[512];
            const ssize_t n = ::recv(fd, buffer, sizeof buffer, 0);
            if (n > 0) {
                reply.append(buffer, static_cast<size_t>(n));
            }
        }
    }
    REQUIRE(reply.find("libspinplatformshellwhoami") != std::string::npos);
    REQUIRE(reply.find("platform shell") == std::string::npos);
    REQUIRE(reply.find("rm -rf") == std::string::npos);
    ::close(fd);
    server.stop();
}

TEST_CASE("hosted arm64 mach-o loads") {
    const std::string source = source_path("hosted.c");
    const std::string output = fixture_path("hosted");
    const std::string built = ensure_built(output,
                                            {"/usr/bin/clang", "-arch", "arm64", "-O0", "-g", "-o", output, source},
                                            source);
    if (built.empty()) {
        SKIP("host compiler could not build the arm64 fixture");
    }
    fathom::Program program = fathom::load_program(built);
    REQUIRE(program.format == fathom::Format::MachO);
    REQUIRE(program.arch == fathom::Arch::Arm64);
    REQUIRE(program.entry_known);
    fathom::analyze(program, {});
    REQUIRE_FALSE(program.instructions.empty());
    REQUIRE(fathom::render_summary(program).find("fathom") != std::string::npos);
    REQUIRE(fathom::find_symbol(program, "main") != nullptr);
}

TEST_CASE("elf and coff objects load when the cross compiler works") {
    const std::string source = source_path("fixture.c");
    const std::string elf = fixture_path("fixture.elf.o");
    const std::string coff = fixture_path("fixture.coff.o");
    const std::string elf_built = ensure_built(
        elf, {FATHOM_CLANG22, "-target", "aarch64-unknown-linux-gnu", "-c", "-nostdlib", "-O0", "-o", elf, source},
        source);
    const std::string coff_built = ensure_built(
        coff, {FATHOM_CLANG22, "-target", "x86_64-pc-windows-gnu", "-c", "-nostdlib", "-O0", "-o", coff, source},
        source);

    if (!elf_built.empty()) {
        fathom::Program program = fathom::load_program(elf_built);
        REQUIRE(program.format == fathom::Format::Elf);
        REQUIRE(program.relocatable);
        fathom::analyze(program, {});
        bool marker = false;
        for (const auto& text : program.strings) {
            if (text.text.find("FATHOM_MARKER_STRING") != std::string::npos) {
                marker = true;
            }
        }
        REQUIRE(marker);
    } else {
        WARN("elf object was not produced");
    }

    if (!coff_built.empty()) {
        fathom::Program program = fathom::load_program(coff_built);
        REQUIRE(program.format == fathom::Format::Coff);
        REQUIRE(program.relocatable);
        fathom::analyze(program, {});
        bool marker = false;
        for (const auto& text : program.strings) {
            if (text.text.find("FATHOM_MARKER_STRING") != std::string::npos) {
                marker = true;
            }
        }
        REQUIRE(marker);
    } else {
        WARN("coff object was not produced");
    }
}

#ifndef FATHOM_SANITIZED
TEST_CASE("debugserver breakpoint lands on main") {
    const std::string source = source_path("spin.c");
    const std::string output = fixture_path("spin");
    const std::string built = ensure_built(
        output, {"/usr/bin/clang", "-arch", "arm64", "-O0", "-g", "-o", output, source}, source);
    if (built.empty()) {
        SKIP("host compiler could not build the spin fixture");
    }
    fathom::Program program;
    try {
        program = fathom::load_program(built);
        fathom::analyze(program, {});
    } catch (const fathom::Error& error) {
        SKIP(error.what());
    }
    const fathom::Symbol* main_symbol = fathom::find_symbol(program, "main");
    if (main_symbol == nullptr) {
        SKIP("spin fixture has no main symbol");
    }
    fathom::DebugSession session;
    try {
        session.set_run_timeout_ms(8000);
        session.launch({built});
    } catch (const fathom::Error& error) {
        SKIP(error.what());
    }
    const auto modules = session.modules();
    std::optional<uint64_t> load;
    for (const auto& module : modules) {
        if (module.path == built || fathom::base_name(module.path) == fathom::base_name(built)) {
            load = module.load_address;
        }
    }
    INFO(session.log());
    REQUIRE(load.has_value());
    const uint64_t breakpoint = fathom::runtime_address(program, *load, main_symbol->address);
    INFO("static " << main_symbol->address << " load " << *load << " image " << program.image_base << " bp "
                   << breakpoint << " entry-pc " << session.stop().pc);
    REQUIRE(session.add_breakpoint(breakpoint));
    session.cont();
    INFO(session.stop().summary);
    INFO(session.log());
    REQUIRE(session.stop().pc == breakpoint);
    const auto memory = session.read_memory(breakpoint, 4);
    REQUIRE(memory.size() == 4);
    const int inferior = session.pid();
    char before_path[PROC_PIDPATHINFO_MAXSIZE] = {};
    REQUIRE(::proc_pidpath(inferior, before_path, sizeof before_path) > 0);
    REQUIRE(std::string(before_path) == built);
    session.shutdown();
    bool gone = false;
    int last_errno = 0;
    for (int i = 0; i < 50; ++i) {
        errno = 0;
        if (::kill(inferior, 0) == -1 && errno == ESRCH) {
            gone = true;
            break;
        }
        last_errno = errno;
        ::usleep(20 * 1000);
    }
    INFO("pid " << inferior << " errno " << last_errno);
    REQUIRE(gone);
}
#endif
