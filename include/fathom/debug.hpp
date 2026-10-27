#pragma once

#include "fathom/program.hpp"

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fathom {

struct DebugModule {
    std::string path;
    uint64_t load_address = 0;
};

struct DebugRegister {
    unsigned index = 0;
    std::string name;
    unsigned bits = 0;
    std::string hex;
    uint64_t value = 0;
    bool is_pc = false;
};

struct StopState {
    int signal = 0;
    uint64_t thread = 0;
    uint64_t pc = 0;
    std::string summary;
    std::vector<DebugRegister> registers;
};

// Local debugger. It spawns Xcode debugserver and speaks the GDB remote
// protocol to a program the user named, or to a pid the user named.
// It does not hide from the target and it does not inject code.
class DebugSession {
public:
    DebugSession();
    ~DebugSession();
    DebugSession(const DebugSession&) = delete;
    DebugSession& operator=(const DebugSession&) = delete;

    void launch(const std::vector<std::string>& program_and_args,
                const std::string& debugserver = {});
    void attach(int pid, const std::string& debugserver = {});

    void cont();
    void step();
    bool add_breakpoint(uint64_t runtime_address);
    bool remove_breakpoint(uint64_t runtime_address);
    std::vector<uint8_t> read_memory(uint64_t address, size_t length);
    std::vector<DebugModule> modules();
    void set_run_timeout_ms(int timeout_ms) { run_timeout_ms_ = timeout_ms > 0 ? timeout_ms : 1000; }
    const StopState& stop() const { return stop_; }
    int pid() const { return inferior_pid_; }
    const std::string& log() const { return log_; }

    void shutdown();

private:
    void spawn(const std::vector<std::string>& debugserver_argv);
    void handshake();
    void refresh_stop(const std::string& packet);
    void load_register_names();
    void ensure_pc();
    void wait_for_stop();
    void drain_available();
    std::string roundtrip(const std::string& payload, int timeout_ms, bool can_block);
    std::string read_packet();
    void send_packet(const std::string& payload);
    void fill_recv(int timeout_ms);

    int child_pid_ = -1;
    int sock_ = -1;
    int log_fd_ = -1;
    bool noack_ = false;
    int inferior_pid_ = -1;
    std::string rx_;
    size_t rx_pos_ = 0;
    std::string log_;
    StopState stop_;
    std::vector<DebugRegister> names_;
    unsigned pc_index_ = 0;
    bool pc_known_ = false;
    int breakpoint_kind_ = 4;
    int io_timeout_ms_ = 3000;
    bool attached_ = false;
    std::string last_tx_;
    int nak_retries_ = 0;
    int run_timeout_ms_ = 120000;
};

void debug_repl(Program* program, DebugSession& session, std::istream& in, std::ostream& out);

// One debugger command. Returns false when the line asks to leave the session.
bool handle_debug_line(Program* program, DebugSession& session, std::string_view line, std::ostream& out);

uint64_t runtime_address(const Program& program, uint64_t load_address, uint64_t static_address);

// Two lowercase hex digits. Sum of the payload bytes, truncated to 8 bits.
std::string rsp_checksum(std::string_view payload);

// First GDB packet in a buffer. A stop reply is accepted on the first '#' even
// when debugserver's checksum bytes do not match. Incomplete input returns
// nullopt and does not consume the buffer.
struct RspFrame {
    std::string payload;
    bool checksum_match = false;
    size_t consumed = 0;
};

std::optional<RspFrame> rsp_take_frame(std::string_view buffer);

}  // namespace fathom
