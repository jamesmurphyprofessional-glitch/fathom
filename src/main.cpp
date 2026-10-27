#include "fathom/debug.hpp"
#include "fathom/engine.hpp"
#include "fathom/retsync.hpp"
#include "fathom/util.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace fathom {
namespace {

struct Invocation {
    std::string command;
    std::string file;
    std::vector<std::string> args;
    Options options;
    bool as_json = false;
    bool as_dot = false;
    bool file_offset = false;
    bool find_bytes = false;
    bool allow_remote = false;
    std::string host = "127.0.0.1";
    int port = 9100;
    std::string debugserver;
    std::string out_dir;
    size_t length = 256;
    size_t limit = 200;
};

void print_usage(std::ostream& out) {
    out << "fathom " << kVersion << "\n"
        << "Local loader, disassembler, triage, debugger, and ret-sync listener.\n"
        << "Structural listings are not Hex-Rays decompiler output.\n\n"
        << "  fathom <file>\n"
        << "  fathom inspect|triage|functions|strings|objects <file>\n"
        << "  fathom disasm|decompile|cfg <file> [function] [--dot]\n"
        << "  fathom xrefs <file> <address|name>\n"
        << "  fathom hex <file> <address> [--len N] [--file]\n"
        << "  fathom find <file> <text>\n"
        << "  fathom find <file> --bytes <hex>\n"
        << "  fathom report <file> [--json]\n"
        << "  fathom explore <file>\n"
        << "  fathom debug launch <program> [args...]\n"
        << "  fathom debug attach <pid>\n"
        << "  fathom sync serve <file> [--host H] [--port N]\n"
        << "  fathom batch <directory> --out <directory>\n"
        << "  fathom version\n\n"
        << "  --slice NAME       universal Mach-O slice\n"
        << "  --max-bytes N      refuse files larger than N (default 256 MiB)\n"
        << "  --limit N          cap string and list output\n"
        << "  --debugserver PATH override the debugserver binary\n"
        << "  --allow-remote     bind ret-sync off loopback with no authentication\n";
}

bool known_command(std::string_view text) {
    static constexpr const char* kCommands[] = {
        "inspect", "triage", "disasm", "decompile", "functions", "strings", "xrefs", "cfg",
        "objects", "hex",    "find",   "report",    "explore",   "debug",   "sync",   "batch",
        "version", "help",
    };
    for (const char* command : kCommands) {
        if (text == command) {
            return true;
        }
    }
    return false;
}

uint64_t parse_count(const std::string& text, const std::string& name) {
    if (text.empty()) {
        throw Error(name + " needs a number");
    }
    for (unsigned char c : text) {
        if (c < '0' || c > '9') {
            throw Error(name + " needs a positive number");
        }
    }
    try {
        return std::stoull(text);
    } catch (const std::exception&) {
        throw Error(name + " is out of range");
    }
}

bool needs_file(const std::string& command) {
    return command != "version" && command != "help" && command != "debug";
}

Invocation parse_args(int argc, char** argv) {
    Invocation inv;
    std::vector<std::string> positionals;
    bool options_done = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (!options_done && arg == "--") {
            options_done = true;
            continue;
        }
        if (!options_done && arg.starts_with("--")) {
            auto value = [&](const std::string& name) {
                if (i + 1 >= argc) {
                    throw Error(name + " needs a value");
                }
                return std::string(argv[++i]);
            };
            if (arg == "--help") {
                inv.command = "help";
            } else if (arg == "--json") {
                inv.as_json = true;
            } else if (arg == "--dot") {
                inv.as_dot = true;
            } else if (arg == "--file") {
                inv.file_offset = true;
            } else if (arg == "--bytes") {
                inv.find_bytes = true;
            } else if (arg == "--allow-remote") {
                inv.allow_remote = true;
            } else if (arg == "--slice") {
                inv.options.slice = value(arg);
            } else if (arg == "--max-bytes") {
                inv.options.max_file_bytes = parse_count(value(arg), arg);
            } else if (arg == "--limit") {
                inv.limit = static_cast<size_t>(parse_count(value(arg), arg));
            } else if (arg == "--len") {
                inv.length = static_cast<size_t>(parse_count(value(arg), arg));
            } else if (arg == "--host") {
                inv.host = value(arg);
            } else if (arg == "--port") {
                const auto port = parse_count(value(arg), arg);
                if (port > 65535) {
                    throw Error("--port is out of range");
                }
                inv.port = static_cast<int>(port);
            } else if (arg == "--debugserver") {
                inv.debugserver = value(arg);
            } else if (arg == "--out") {
                inv.out_dir = value(arg);
            } else {
                throw Error("unknown option " + arg);
            }
            continue;
        }
        positionals.push_back(arg);
    }

    if (inv.command.empty()) {
        if (!positionals.empty() && known_command(positionals.front())) {
            inv.command = positionals.front();
            positionals.erase(positionals.begin());
        } else if (!positionals.empty()) {
            inv.command = "inspect";
        } else {
            inv.command = "help";
        }
    }

    if (inv.command == "debug") {
        if (positionals.empty()) {
            throw Error("debug needs launch or attach");
        }
        const std::string sub = positionals.front();
        positionals.erase(positionals.begin());
        if (sub == "launch") {
            if (positionals.empty()) {
                throw Error("debug launch needs a program");
            }
            inv.file = positionals.front();
            inv.args = positionals;
        } else if (sub == "attach") {
            if (positionals.size() != 1) {
                throw Error("debug attach needs one pid");
            }
            inv.args = positionals;
        } else {
            throw Error("debug action must be launch or attach");
        }
        return inv;
    }
    if (inv.command == "sync") {
        if (positionals.empty() || positionals.front() != "serve") {
            throw Error("sync needs: sync serve <file>");
        }
        positionals.erase(positionals.begin());
        if (positionals.size() != 1) {
            throw Error("sync serve needs one file");
        }
        inv.file = positionals.front();
        return inv;
    }
    if (inv.command == "batch") {
        if (positionals.size() != 1) {
            throw Error("batch needs one directory");
        }
        if (inv.out_dir.empty()) {
            throw Error("batch needs --out");
        }
        inv.file = positionals.front();
        return inv;
    }
    if (needs_file(inv.command)) {
        if (positionals.empty()) {
            throw Error(inv.command + " needs a file");
        }
        inv.file = positionals.front();
        positionals.erase(positionals.begin());
        inv.args = std::move(positionals);
    }
    return inv;
}

Program open_analyzed(const Invocation& inv) {
    Program program = load_program(inv.file, inv.options);
    analyze(program, inv.options);
    return program;
}

std::string join_args(const std::vector<std::string>& args) {
    std::string out;
    for (const auto& arg : args) {
        if (!out.empty()) {
            out.push_back(' ');
        }
        out += arg;
    }
    return out;
}

std::string sanitize_name(std::string_view name) {
    std::string out;
    out.reserve(name.size());
    for (unsigned char c : name) {
        if (std::isalnum(c) || c == '.' || c == '_' || c == '-') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('_');
        }
    }
    while (!out.empty() && (out.front() == '.' || out.front() == '-')) {
        out.erase(out.begin());
    }
    if (out.empty()) {
        out = "file";
    }
    if (out.size() > 80) {
        out.resize(80);
    }
    return out;
}

void apply_sync(Program* program, RetSyncServer* sync, uint64_t& cursor, bool& cursor_valid, uint64_t& seen,
                std::ostream& out) {
    if (sync == nullptr) {
        return;
    }
    const SyncState state = sync->state();
    if (state.messages != seen) {
        if (state.location_valid) {
            cursor = state.static_va;
            cursor_valid = true;
            out << "sync " << hex_addr(state.static_va);
            if (!state.module_path.empty()) {
                out << "  " << state.module_path;
            }
            out << "\n";
        }
        if (!state.last_error.empty()) {
            out << "sync note: " << state.last_error << "\n";
        }
        if (program != nullptr) {
            std::erase_if(program->comments, [](const Comment& comment) {
                return comment.source.starts_with("ret-sync");
            });
            program->comments.insert(program->comments.end(), state.comments.begin(), state.comments.end());
        }
        seen = state.messages;
    }
}

void run_repl(Program* program, DebugSession* debug, RetSyncServer* sync, std::istream& in, std::ostream& out) {
    uint64_t cursor = 0;
    bool cursor_valid = false;
    if (program != nullptr && program->entry_known) {
        cursor = program->entry;
        cursor_valid = true;
    }
    uint64_t seen = 0;
    bool warned = false;
    out << "fathom " << kVersion << ". help lists commands.\n";
    if (debug != nullptr) {
        out << debug->stop().summary << "\n";
    }
    std::string line;
    while (std::getline(in, line)) {
        apply_sync(program, sync, cursor, cursor_valid, seen, out);
        size_t begin = 0;
        while (begin < line.size() && std::isspace(static_cast<unsigned char>(line[begin]))) {
            ++begin;
        }
        size_t end = line.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(line[end - 1]))) {
            --end;
        }
        const std::string text = line.substr(begin, end - begin);
        if (text.empty()) {
            continue;
        }
        const auto gap = text.find_first_of(" \t");
        const std::string word = gap == std::string::npos ? text : text.substr(0, gap);
        const std::string rest = gap == std::string::npos ? std::string() : text.substr(gap + 1);
        try {
            if (word == "q" || word == "quit") {
                return;
            }
            if (word == "help" || word == "?") {
                out << "info triage funcs strings xrefs dis dec cfg objects hex find findx goto\n"
                    << "c s n b d r m mods     debugger, when one is attached\n"
                    << "dbg <line>             send one line to the ret-sync debugger\n"
                    << "sync                   show the ret-sync cursor\n"
                    << "q                      leave\n";
                continue;
            }
            if (word == "sync") {
                if (sync == nullptr) {
                    out << "ret-sync is not listening. fathom sync serve <file>\n";
                } else {
                    const SyncState state = sync->state();
                    out << "listening on " << sync->port() << " connected " << (state.connected ? "yes" : "no")
                        << "\n";
                    if (state.location_valid) {
                        out << "static " << hex_addr(state.static_va) << " runtime " << hex_addr(state.runtime_pc)
                            << "\n";
                    }
                }
                continue;
            }
            if (word == "dbg") {
                if (sync == nullptr) {
                    out << "ret-sync is not listening\n";
                    continue;
                }
                if (!warned) {
                    out << "the connected debugger executes this line\n";
                    warned = true;
                }
                const auto command = rest;
                auto first = command.find_first_not_of(" \t");
                if (first == std::string::npos) {
                    out << "dbg needs the debugger command\n";
                    continue;
                }
                sync->send_debugger_command(command.substr(first));
                continue;
            }
            if (debug != nullptr && (word == "c" || word == "cont" || word == "continue" || word == "s" ||
                                     word == "si" || word == "step" || word == "n" || word == "next" || word == "b" ||
                                     word == "break" || word == "d" || word == "delete" || word == "clear" ||
                                     word == "r" || word == "regs" || word == "m" || word == "x" || word == "mem" ||
                                     word == "mods" || word == "modules" || word == "dis" || word == "disasm")) {
                if (!handle_debug_line(program, *debug, text, out)) {
                    return;
                }
                continue;
            }
            if (program == nullptr) {
                out << "no program is open\n";
                continue;
            }
            const std::string at = rest.empty() && cursor_valid ? hex_addr(cursor) : rest;
            if (word == "info") {
                out << render_summary(*program);
            } else if (word == "triage") {
                out << render_triage(*program);
            } else if (word == "funcs" || word == "functions") {
                out << render_functions(*program);
            } else if (word == "strings") {
                const size_t limit = rest.empty() ? 50 : static_cast<size_t>(parse_count(rest, "limit"));
                out << render_strings(*program, limit);
            } else if (word == "xrefs") {
                out << render_xrefs(*program, at);
            } else if (word == "dis") {
                out << render_disasm(*program, at, 80);
            } else if (word == "dec" || word == "decompile") {
                out << render_decompile(*program, at);
            } else if (word == "cfg") {
                out << render_cfg(*program, at);
            } else if (word == "objects") {
                out << render_objects(*program);
            } else if (word == "hex") {
                uint64_t origin = cursor;
                if (!rest.empty()) {
                    if (const auto parsed = parse_address(rest)) {
                        origin = *parsed;
                    } else {
                        out << "hex needs an address\n";
                        continue;
                    }
                }
                out << render_hex(*program, origin, true, 128);
            } else if (word == "find") {
                out << render_find_text(*program, rest);
            } else if (word == "findx") {
                const auto bytes = parse_hex_bytes(rest);
                if (!bytes) {
                    out << "findx needs hex bytes\n";
                    continue;
                }
                out << render_find_bytes(*program, *bytes);
            } else if (word == "goto") {
                if (const auto parsed = parse_address(rest)) {
                    cursor = *parsed;
                    cursor_valid = true;
                    out << "cursor " << hex_addr(cursor) << "\n";
                } else if (const Function* function = find_function(*program, rest)) {
                    cursor = function->address;
                    cursor_valid = true;
                    out << "cursor " << hex_addr(cursor) << "  " << function->name << "\n";
                } else {
                    out << "unknown address or function\n";
                }
            } else if (word == "cursor") {
                out << (cursor_valid ? hex_addr(cursor) : std::string("unset")) << "\n";
            } else {
                out << "unknown command. help lists them.\n";
            }
        } catch (const Error& error) {
            out << "error: " << error.what() << "\n";
        }
    }
}

int run_batch(const Invocation& inv) {
    namespace fs = std::filesystem;
    std::error_code error;
    const fs::path root(inv.file);
    if (!fs::is_directory(root, error)) {
        throw Error("batch input is not a directory: " + inv.file);
    }
    const fs::path out_root(inv.out_dir);
    fs::create_directories(out_root, error);
    if (error) {
        throw Error("cannot create " + inv.out_dir + ": " + error.message());
    }
    const fs::path out_canon = fs::weakly_canonical(out_root, error);
    if (error) {
        throw Error("cannot resolve " + inv.out_dir);
    }
    size_t seen = 0;
    size_t written = 0;
    for (const fs::directory_entry& entry : fs::directory_iterator(root)) {
        if (seen >= 10000) {
            std::cerr << "fathom: stopped at 10000 directory entries\n";
            break;
        }
        ++seen;
        std::error_code entry_error;
        if (entry.is_symlink(entry_error) || !entry.is_regular_file(entry_error)) {
            continue;
        }
        const fs::path canon = fs::weakly_canonical(entry.path(), entry_error);
        if (!entry_error) {
            const std::string out_text = out_canon.string();
            const std::string file_text = canon.string();
            if (file_text == out_text || file_text.starts_with(out_text + "/")) {
                continue;
            }
        }
        const std::string safe = sanitize_name(entry.path().filename().string());
        fs::path dest = out_canon / (safe + ".json");
        for (int suffix = 1; fs::exists(dest) && suffix < 10000; ++suffix) {
            dest = out_canon / (safe + "_" + std::to_string(suffix) + ".json");
        }
        if (dest.parent_path() != out_canon) {
            throw Error("refusing a batch output path outside --out");
        }
        std::ofstream output(dest);
        if (!output) {
            throw Error("cannot write " + dest.string());
        }
        try {
            Program program = load_program(entry.path().string(), inv.options);
            analyze(program, inv.options);
            output << render_json(program);
        } catch (const Error& failure) {
            nlohmann::json document;
            document["error"] = failure.what();
            document["path"] = entry.path().filename().string();
            output << document.dump(2) << "\n";
        }
        ++written;
    }
    std::cout << "wrote " << written << " reports to " << out_canon.string() << "\n";
    return 0;
}

int dispatch(const Invocation& inv) {
    if (inv.command == "help") {
        print_usage(std::cout);
        return 0;
    }
    if (inv.command == "version") {
        std::cout << "fathom " << kVersion << "\n"
                  << "ret-sync wire protocol, client plugins from " << kRetSyncUpstream << "\n"
                  << "those plugins are not linked into this binary\n";
        return 0;
    }
    if (inv.command == "batch") {
        return run_batch(inv);
    }
    if (inv.command == "debug" && !inv.args.empty() && inv.file.empty()) {
        const int pid = static_cast<int>(parse_count(inv.args.front(), "pid"));
        DebugSession session;
        session.attach(pid, inv.debugserver);
        run_repl(nullptr, &session, nullptr, std::cin, std::cout);
        session.shutdown();
        return 0;
    }

    Program program;
    Program* loaded = nullptr;
    if (!inv.file.empty() && inv.command != "debug") {
        program = open_analyzed(inv);
        loaded = &program;
    } else if (inv.command == "debug" && !inv.file.empty()) {
        try {
            program = open_analyzed(inv);
            loaded = &program;
        } catch (const Error& error) {
            std::cerr << "fathom: static load failed: " << error.what() << "\n";
        }
    }

    if (inv.command == "inspect") {
        std::cout << (inv.as_json ? render_json(program) : render_summary(program));
    } else if (inv.command == "triage") {
        std::cout << render_triage(program);
    } else if (inv.command == "functions") {
        std::cout << render_functions(program);
    } else if (inv.command == "strings") {
        std::cout << render_strings(program, inv.limit);
    } else if (inv.command == "objects") {
        std::cout << render_objects(program);
    } else if (inv.command == "disasm") {
        std::cout << render_disasm(program, join_args(inv.args), inv.limit == 200 ? 200 : inv.limit);
    } else if (inv.command == "decompile") {
        std::cout << render_decompile(program, join_args(inv.args));
    } else if (inv.command == "cfg") {
        std::cout << (inv.as_dot ? render_dot(program, join_args(inv.args))
                                 : render_cfg(program, join_args(inv.args)));
    } else if (inv.command == "xrefs") {
        if (inv.args.empty()) {
            throw Error("xrefs needs an address or name");
        }
        std::cout << render_xrefs(program, join_args(inv.args));
    } else if (inv.command == "hex") {
        if (inv.args.empty()) {
            throw Error("hex needs an address or file offset");
        }
        const auto origin = parse_address(inv.args.front());
        if (!origin) {
            throw Error("hex address is not a number");
        }
        std::cout << render_hex(program, *origin, !inv.file_offset, inv.length);
    } else if (inv.command == "find") {
        if (inv.find_bytes) {
            const auto bytes = parse_hex_bytes(join_args(inv.args));
            if (!bytes) {
                throw Error("find --bytes needs an even run of hex digits");
            }
            std::cout << render_find_bytes(program, *bytes);
        } else {
            if (inv.args.empty()) {
                throw Error("find needs text");
            }
            std::cout << render_find_text(program, join_args(inv.args));
        }
    } else if (inv.command == "report") {
        std::cout << (inv.as_json ? render_json(program) : render_summary(program) + render_triage(program));
    } else if (inv.command == "explore") {
        run_repl(loaded, nullptr, nullptr, std::cin, std::cout);
    } else if (inv.command == "debug") {
        DebugSession session;
        session.launch(inv.args, inv.debugserver);
        run_repl(loaded, &session, nullptr, std::cin, std::cout);
        session.shutdown();
    } else if (inv.command == "sync") {
        if (inv.allow_remote) {
            std::cerr << "warning: ret-sync will listen on " << inv.host
                      << " with no authentication. Peer bytes are parsed and are not executed.\n";
        }
        RetSyncServer server(program);
        server.start(inv.host, static_cast<uint16_t>(inv.port), inv.allow_remote);
        std::cout << "ret-sync listening on " << inv.host << ":" << server.port() << "\n"
                  << "from lldb: command script import third_party/ret-sync/ext_lldb/sync.py\n"
                  << "then: sync " << (inv.host == "127.0.0.1" ? "127.0.0.1" : inv.host) << "\n";
        run_repl(loaded, nullptr, &server, std::cin, std::cout);
        server.stop();
    } else {
        throw Error("unknown command " + inv.command);
    }
    return 0;
}

}  // namespace
}  // namespace fathom

int main(int argc, char** argv) {
    try {
        return fathom::dispatch(fathom::parse_args(argc, argv));
    } catch (const fathom::Error& error) {
        std::cerr << "fathom: " << error.what() << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "fathom: " << error.what() << "\n";
        return 1;
    }
}
