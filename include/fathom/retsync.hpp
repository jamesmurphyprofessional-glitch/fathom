#pragma once

#include "fathom/program.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace fathom {

// Cursor published by a ret-sync debugger plugin (LLDB, GDB, WinDbg, x64dbg).
// Addresses in the protocol are runtime addresses. static_va is the address in
// the loaded Program after subtracting the ASLR slide.
struct SyncState {
    bool connected = false;
    std::string dialect;
    std::string identity;
    std::string module_path;
    uint64_t runtime_base = 0;
    uint64_t runtime_pc = 0;
    uint64_t static_va = 0;
    bool location_valid = false;
    uint64_t messages = 0;
    std::string last_error;
    // Comments collected from the peer. The server thread does not write these
    // into Program; the session that owns the program copies them across.
    std::vector<Comment> comments;
};

uint64_t rebase_to_static(uint64_t preferred_base, uint64_t runtime_base, uint64_t runtime_pc);

// Disassembler side of ret-sync. Listens for the newline-delimited notices the
// upstream debugger plugins send to port 9100. Peer bytes are parsed as
// protocol messages. They are never passed to a shell.
class RetSyncServer {
public:
    explicit RetSyncServer(Program& program);
    ~RetSyncServer();
    RetSyncServer(const RetSyncServer&) = delete;
    RetSyncServer& operator=(const RetSyncServer&) = delete;

    // host must be a loopback address unless allow_remote is set. The listener
    // is unauthenticated either way.
    void start(const std::string& host, uint16_t port, bool allow_remote);
    void stop();
    uint16_t port() const { return port_; }
    SyncState state() const;
    bool wait_location(std::chrono::milliseconds timeout);
    // Sends one line to the connected debugger plugin, which executes it in
    // that debugger. The line is the text the local user typed.
    void send_debugger_command(const std::string& line);

private:
    void thread_main();
    void handle_client(int client);
    void handle_line(const std::string& line, int client);

    Program& program_;
    std::string host_;
    uint16_t port_ = 0;
    int listen_fd_ = -1;
    int client_fd_ = -1;
    bool allow_remote_ = false;
    std::thread thread_;
    mutable std::mutex mu_;
    std::mutex write_mu_;
    std::condition_variable cv_;
    bool stop_ = false;
    SyncState state_;
    uint64_t location_generation_ = 0;
};

}  // namespace fathom
