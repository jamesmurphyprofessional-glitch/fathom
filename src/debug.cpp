#include "fathom/debug.hpp"

#include "fathom/engine.hpp"
#include "fathom/util.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <sstream>
#include <string>

extern char** environ;

#ifndef FATHOM_DEBUGSERVER
#define FATHOM_DEBUGSERVER \
    "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver"
#endif

namespace fathom {
namespace {

constexpr int kPacketCap = 4 * 1024 * 1024;

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

std::string tail_text(std::string_view text, size_t max_chars) {
    if (text.size() <= max_chars) {
        return std::string(text);
    }
    return std::string(text.substr(text.size() - max_chars));
}

uint16_t reserve_loopback_port() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw Error("cannot reserve a debugger port");
    }
    const int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    if (::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
        ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0) {
        ::close(fd);
        throw Error("cannot reserve a loopback debugger port");
    }
    sockaddr_in actual {};
    socklen_t length = sizeof actual;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &length) != 0) {
        ::close(fd);
        throw Error("cannot read the reserved debugger port");
    }
    const uint16_t port = ntohs(actual.sin_port);
    ::close(fd);
    if (port == 0) {
        throw Error("reserved debugger port was 0");
    }
    return port;
}

std::string trim_copy(std::string_view text) {
    size_t begin = 0;
    while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) {
        ++begin;
    }
    size_t end = text.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
        --end;
    }
    return std::string(text.substr(begin, end - begin));
}

uint64_t parse_le_hex(std::string_view text) {
    uint64_t value = 0;
    const size_t bytes = std::min(text.size() / 2, static_cast<size_t>(8));
    for (size_t i = 0; i < bytes; ++i) {
        const int hi = hex_nibble(text[i * 2]);
        const int lo = hex_nibble(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            break;
        }
        value |= static_cast<uint64_t>((hi << 4) | lo) << (8 * i);
    }
    return value;
}

std::optional<uint64_t> parse_hex_key(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }
    uint64_t value = 0;
    for (char c : text) {
        const int digit = hex_nibble(c);
        if (digit < 0) {
            return std::nullopt;
        }
        value = (value << 4) | static_cast<uint64_t>(digit);
    }
    return value;
}

std::string decode_rle(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        const char c = raw[i];
        if (c == '*' && i + 1 < raw.size() && !out.empty()) {
            const auto repeat = static_cast<unsigned char>(raw[++i]);
            const int count = static_cast<int>(repeat) - 29;
            if (count >= 2 && count <= 126) {
                out.append(static_cast<size_t>(count - 1), out.back());
                continue;
            }
            out.push_back('*');
            out.push_back(static_cast<char>(repeat));
            continue;
        }
        out.push_back(c);
    }
    return out;
}

bool memory_reply(std::string_view text) {
    if (text.empty() || text[0] == 'E') {
        return false;
    }
    bool star = false;
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '*') {
            star = true;
            if (i + 1 >= text.size()) {
                return false;
            }
            ++i;
            continue;
        }
        if (hex_nibble(c) < 0) {
            return false;
        }
    }
    return star;
}

void write_all(int fd, std::string_view bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
        const ssize_t n = ::send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw Error("debugger write failed: " + std::string(std::strerror(errno)));
        }
        if (n == 0) {
            throw Error("debugger write returned no bytes");
        }
        sent += static_cast<size_t>(n);
    }
}

std::optional<uint64_t> json_u64(const nlohmann::json& value) {
    try {
        if (value.is_number_unsigned()) {
            return value.get<uint64_t>();
        }
        if (value.is_number_integer()) {
            const auto signed_value = value.get<int64_t>();
            if (signed_value < 0) {
                return std::nullopt;
            }
            return static_cast<uint64_t>(signed_value);
        }
        if (value.is_string()) {
            return parse_address(value.get<std::string>());
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return std::nullopt;
}

std::vector<DebugModule> modules_from_json(std::string_view reply) {
    const auto open = reply.find('{');
    const auto close = reply.rfind('}');
    if (open == std::string_view::npos || close == std::string_view::npos || close <= open) {
        return {};
    }
    nlohmann::json document;
    try {
        document = nlohmann::json::parse(reply.substr(open, close - open + 1));
    } catch (const std::exception&) {
        return {};
    }
    if (!document.contains("images") || !document["images"].is_array()) {
        return {};
    }
    std::vector<DebugModule> modules;
    for (const auto& image : document["images"]) {
        if (!image.is_object()) {
            continue;
        }
        DebugModule module;
        if (image.contains("pathname") && image["pathname"].is_string()) {
            module.path = image["pathname"].get<std::string>();
        } else if (image.contains("path") && image["path"].is_string()) {
            module.path = image["path"].get<std::string>();
        }
        if (image.contains("load_address")) {
            if (const auto address = json_u64(image["load_address"])) {
                module.load_address = *address;
            }
        }
        if (!module.path.empty()) {
            modules.push_back(std::move(module));
        }
    }
    return modules;
}

std::vector<DebugModule> modules_from_scan(std::string_view reply) {
    std::vector<DebugModule> modules;
    size_t pos = 0;
    while (pos < reply.size()) {
        auto key = reply.find("\"pathname\"", pos);
        const auto path_key = reply.find("\"path\"", pos);
        if (key == std::string_view::npos || (path_key != std::string_view::npos && path_key < key)) {
            key = path_key;
        }
        if (key == std::string_view::npos) {
            break;
        }
        const auto colon = reply.find(':', key);
        if (colon == std::string_view::npos) {
            break;
        }
        const auto q1 = reply.find('"', colon + 1);
        if (q1 == std::string_view::npos) {
            break;
        }
        const auto q2 = reply.find('"', q1 + 1);
        if (q2 == std::string_view::npos) {
            break;
        }
        DebugModule module;
        module.path = std::string(reply.substr(q1 + 1, q2 - q1 - 1));
        const size_t window = key > 220 ? key - 220 : 0;
        const size_t window_end = std::min(reply.size(), q2 + 220);
        const auto mark = reply.find("load_address", window);
        if (mark != std::string_view::npos && mark < window_end) {
            const auto value_at = reply.find(':', mark);
            if (value_at != std::string_view::npos && value_at < window_end) {
                size_t i = value_at + 1;
                while (i < reply.size() && (reply[i] == ' ' || reply[i] == '"')) {
                    ++i;
                }
                int base = 10;
                if (i + 1 < reply.size() && reply[i] == '0' && (reply[i + 1] == 'x' || reply[i + 1] == 'X')) {
                    base = 16;
                    i += 2;
                }
                uint64_t value = 0;
                bool any = false;
                while (i < reply.size()) {
                    const int digit = hex_nibble(reply[i]);
                    if (digit < 0 || digit >= base) {
                        break;
                    }
                    any = true;
                    value = value * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
                    ++i;
                }
                if (any) {
                    module.load_address = value;
                }
            }
        }
        if (!module.path.empty()) {
            modules.push_back(std::move(module));
        }
        pos = q2 + 1;
    }
    return modules;
}

std::optional<uint64_t> matching_load(const Program& program, const std::vector<DebugModule>& modules) {
    const std::string want = base_name(program.path);
    for (const auto& module : modules) {
        if (module.path == program.path || iequals(base_name(module.path), want)) {
            return module.load_address;
        }
    }
    return std::nullopt;
}

void print_bytes(std::ostream& out, uint64_t address, const std::vector<uint8_t>& bytes) {
    for (size_t i = 0; i < bytes.size(); i += 16) {
        out << hex_addr(address + i) << "  ";
        std::string ascii;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < bytes.size()) {
                const unsigned char byte = bytes[i + j];
                out << fmt::format("{:02x} ", byte);
                ascii.push_back(byte >= 0x20 && byte <= 0x7e ? static_cast<char>(byte) : '.');
            } else {
                out << "   ";
            }
        }
        out << " " << ascii << "\n";
    }
}

void print_stop(std::ostream& out, const StopState& stop) {
    out << (stop.summary.empty() ? "stopped" : stop.summary) << "\n";
    size_t shown = 0;
    for (const auto& reg : stop.registers) {
        if (!reg.is_pc && reg.hex.empty()) {
            continue;
        }
        if (!reg.is_pc && shown >= 8) {
            continue;
        }
        out << "  " << (reg.name.empty() ? fmt::format("r{}", reg.index) : reg.name) << " " << hex_addr(reg.value)
            << "\n";
        ++shown;
    }
}

}  // namespace

std::string rsp_checksum(std::string_view payload) {
    unsigned sum = 0;
    for (unsigned char byte : payload) {
        sum = (sum + byte) & 0xff;
    }
    return fmt::format("{:02x}", sum);
}

std::optional<RspFrame> rsp_take_frame(std::string_view buffer) {
    size_t start = 0;
    if (!buffer.empty() && buffer[0] == '+') {
        start = 1;
    } else if (!buffer.empty() && buffer[0] == '-') {
        RspFrame frame;
        frame.payload = "-";
        frame.checksum_match = true;
        frame.consumed = 1;
        return frame;
    }
    if (start >= buffer.size()) {
        return std::nullopt;
    }
    if (buffer[start] != '$') {
        const auto dollar = buffer.find('$', start);
        if (dollar == std::string_view::npos) {
            return std::nullopt;
        }
        start = dollar;
    }
    for (size_t i = start + 1; i < buffer.size(); ++i) {
        if (buffer[i] != '#') {
            continue;
        }
        if (i + 2 >= buffer.size()) {
            return std::nullopt;
        }
        const int hi = hex_nibble(buffer[i + 1]);
        const int lo = hex_nibble(buffer[i + 2]);
        if (hi < 0 || lo < 0) {
            continue;
        }
        RspFrame frame;
        frame.payload.assign(buffer.data() + start + 1, i - (start + 1));
        unsigned got = 0;
        for (unsigned char byte : frame.payload) {
            got = (got + byte) & 0xff;
        }
        frame.checksum_match = got == static_cast<unsigned>((hi << 4) | lo);
        frame.consumed = i + 3;
        return frame;
    }
    return std::nullopt;
}

uint64_t runtime_address(const Program& program, uint64_t load_address, uint64_t static_address) {
    return load_address + (static_address - program.image_base);
}

DebugSession::DebugSession() {
    static bool once = false;
    if (!once) {
        ::signal(SIGPIPE, SIG_IGN);
        once = true;
    }
}

DebugSession::~DebugSession() {
    try {
        shutdown();
    } catch (...) {
    }
}

void DebugSession::launch(const std::vector<std::string>& program_and_args, const std::string& debugserver) {
    if (program_and_args.empty() || program_and_args.front().empty()) {
        throw Error("debug launch needs the program path");
    }
    shutdown();
    attached_ = false;
    const std::string server = debugserver.empty() ? std::string(FATHOM_DEBUGSERVER) : debugserver;
    std::vector<std::string> argv;
    argv.push_back(server);
    argv.emplace_back("127.0.0.1:0");
    argv.insert(argv.end(), program_and_args.begin(), program_and_args.end());
    spawn(argv);
    try {
        handshake();
    } catch (...) {
        shutdown();
        throw;
    }
}

void DebugSession::attach(int pid, const std::string& debugserver) {
    if (pid <= 0) {
        throw Error("debug attach needs a positive pid");
    }
    shutdown();
    attached_ = true;
    const std::string server = debugserver.empty() ? std::string(FATHOM_DEBUGSERVER) : debugserver;
    spawn({server, "127.0.0.1:0", "--attach=" + std::to_string(pid)});
    try {
        handshake();
    } catch (...) {
        shutdown();
        throw;
    }
}

void DebugSession::drain_available() {
    if (log_fd_ < 0) {
        return;
    }
    char buffer[4096];
    while (true) {
        const ssize_t n = ::read(log_fd_, buffer, sizeof buffer);
        if (n > 0) {
            log_.append(buffer, static_cast<size_t>(n));
            continue;
        }
        break;
    }
    if (log_.size() > 1024 * 1024) {
        log_.erase(0, log_.size() - (256 * 1024));
    }
}

void DebugSession::spawn(const std::vector<std::string>& debugserver_argv) {
    if (debugserver_argv.empty()) {
        throw Error("missing debugserver path");
    }
    int pipes[2] = {-1, -1};
    if (::pipe(pipes) != 0) {
        throw Error("cannot create a pipe for debugserver");
    }
    const int flags = ::fcntl(pipes[0], F_GETFL, 0);
    if (flags >= 0) {
        ::fcntl(pipes[0], F_SETFL, flags | O_NONBLOCK);
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipes[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipes[0]);
    posix_spawn_file_actions_addclose(&actions, pipes[1]);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attr, 0);

    const uint16_t port = reserve_loopback_port();
    std::vector<std::string> owned = debugserver_argv;
    for (auto& arg : owned) {
        if (arg == "127.0.0.1:0") {
            arg = "127.0.0.1:" + std::to_string(port);
        }
    }
    std::vector<char*> argv;
    argv.reserve(owned.size() + 1);
    for (auto& arg : owned) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    pid_t pid = 0;
    const int rc = posix_spawn(&pid, owned.front().c_str(), &actions, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    ::close(pipes[1]);
    if (rc != 0) {
        ::close(pipes[0]);
        throw Error("cannot start debugserver: " + std::string(std::strerror(rc)));
    }
    child_pid_ = static_cast<int>(pid);
    log_fd_ = pipes[0];

    try {
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        if (::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
            throw Error("cannot build the loopback debugger address");
        }
        bool connected = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            drain_available();
            int status = 0;
            const pid_t reaped = ::waitpid(child_pid_, &status, WNOHANG);
            if (reaped == child_pid_) {
                child_pid_ = -1;
                throw Error("debugserver exited before accepting a connection:\n" + tail_text(log_, 1500));
            }
            const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) {
                throw Error("cannot open a debugger socket");
            }
            const int one = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
            if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0) {
                timeval timeout {};
                timeout.tv_sec = 3;
                ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
                ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
                sock_ = fd;
                connected = true;
                break;
            }
            ::close(fd);
            ::usleep(20 * 1000);
        }
        if (!connected) {
            throw Error("cannot connect to debugserver on 127.0.0.1:" + std::to_string(port) + "\n" +
                        tail_text(log_, 800));
        }
    } catch (...) {
        shutdown();
        throw;
    }
}

void DebugSession::send_packet(const std::string& payload) {
    if (sock_ < 0) {
        throw Error("debugger is not connected");
    }
    last_tx_ = "$" + payload + "#" + rsp_checksum(payload);
    nak_retries_ = 0;
    write_all(sock_, last_tx_);
}

void DebugSession::fill_recv(int timeout_ms) {
    drain_available();
    pollfd fds[2] {};
    fds[0].fd = sock_;
    fds[0].events = POLLIN;
    nfds_t count = 1;
    if (log_fd_ >= 0) {
        fds[1].fd = log_fd_;
        fds[1].events = POLLIN;
        count = 2;
    }
    const int rc = ::poll(fds, count, std::max(timeout_ms, 0));
    if (rc < 0) {
        if (errno == EINTR) {
            return;
        }
        throw Error("debugger poll failed: " + std::string(std::strerror(errno)));
    }
    if (rc == 0) {
        throw Error("timed out waiting for the debugger");
    }
    if (count == 2 && (fds[1].revents & (POLLIN | POLLHUP)) != 0) {
        drain_available();
    }
    if ((fds[0].revents & POLLIN) == 0) {
        return;
    }
    char buffer[8192];
    const ssize_t n = ::recv(sock_, buffer, sizeof buffer, 0);
    if (n <= 0) {
        throw Error("debugger closed the connection");
    }
    if (rx_.size() + static_cast<size_t>(n) > static_cast<size_t>(kPacketCap)) {
        throw Error("debugger packet exceeded 4 MiB");
    }
    rx_.append(buffer, static_cast<size_t>(n));
}

std::string DebugSession::read_packet() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max(io_timeout_ms_, 1));
    while (true) {
        if (rx_pos_ > 65536) {
            rx_.erase(0, rx_pos_);
            rx_pos_ = 0;
        }
        const std::string_view window(rx_.data() + rx_pos_, rx_.size() - rx_pos_);
        if (const auto frame = rsp_take_frame(window)) {
            rx_pos_ += frame->consumed;
            if (frame->payload == "-") {
                if (nak_retries_ < 1 && !last_tx_.empty()) {
                    ++nak_retries_;
                    write_all(sock_, last_tx_);
                    continue;
                }
                throw Error("debugger rejected a packet");
            }
            if (!noack_) {
                write_all(sock_, "+");
            }
            if (!frame->checksum_match && log_.find("checksum mismatch") == std::string::npos) {
                log_.append("checksum mismatch on a debugger reply\n");
            }
            return frame->payload;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw Error("timed out waiting for the debugger");
        }
        const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        fill_recv(static_cast<int>(std::max<std::chrono::milliseconds::rep>(remain, 1)));
    }
}

std::string DebugSession::roundtrip(const std::string& payload, int timeout_ms, bool can_block) {
    io_timeout_ms_ = can_block ? std::max(timeout_ms, 1000) : timeout_ms;
    send_packet(payload);
    return read_packet();
}

void DebugSession::load_register_names() {
    names_.clear();
    pc_known_ = false;
    pc_index_ = 0;
    for (unsigned index = 0; index < 256; ++index) {
        const std::string reply = roundtrip(fmt::format("qRegisterInfo{:x}", index), 2000, false);
        if (reply.empty() || reply.front() == 'E') {
            break;
        }
        DebugRegister reg;
        reg.index = index;
        size_t cursor = 0;
        while (cursor < reply.size()) {
            const auto semi = reply.find(';', cursor);
            const auto field = reply.substr(cursor, semi == std::string::npos ? std::string::npos : semi - cursor);
            const auto colon = field.find(':');
            if (colon != std::string::npos) {
                const auto key = field.substr(0, colon);
                const auto value = field.substr(colon + 1);
                if (key == "name") {
                    reg.name = value;
                } else if (key == "bitsize") {
                    reg.bits = static_cast<unsigned>(std::strtoul(value.c_str(), nullptr, 10));
                } else if (key == "generic" && (value == "pc" || value == "rip" || value == "eip")) {
                    reg.is_pc = true;
                }
            }
            if (semi == std::string::npos) {
                break;
            }
            cursor = semi + 1;
        }
        if (reg.name == "pc" || reg.name == "rip" || reg.name == "eip") {
            reg.is_pc = true;
        }
        if (reg.is_pc) {
            pc_known_ = true;
            pc_index_ = index;
            if (reg.name == "rip" || reg.name == "eip") {
                breakpoint_kind_ = 1;
            } else if (reg.name == "pc") {
                breakpoint_kind_ = 4;
            }
        }
        names_.push_back(std::move(reg));
    }
    if (names_.empty()) {
        throw Error("debugger returned no register descriptions");
    }
}

void DebugSession::refresh_stop(const std::string& packet) {
    stop_ = {};
    stop_.registers = names_;
    if (packet.empty()) {
        stop_.summary = "empty stop reply";
        return;
    }
    const char kind = packet.front();
    if (kind == 'W') {
        stop_.summary = "process exited";
        return;
    }
    if (kind == 'X') {
        stop_.summary = "process terminated";
        return;
    }
    if ((kind == 'T' || kind == 'S') && packet.size() >= 3) {
        const int hi = hex_nibble(packet[1]);
        const int lo = hex_nibble(packet[2]);
        if (hi >= 0 && lo >= 0) {
            stop_.signal = (hi << 4) | lo;
        }
    }
    if (kind == 'T') {
        size_t cursor = 3;
        while (cursor < packet.size()) {
            const auto colon = packet.find(':', cursor);
            const auto semi = packet.find(';', cursor);
            if (colon == std::string::npos || (semi != std::string::npos && semi < colon)) {
                if (semi == std::string::npos) {
                    break;
                }
                cursor = semi + 1;
                continue;
            }
            const auto key = packet.substr(cursor, colon - cursor);
            const auto end = semi == std::string::npos ? packet.size() : semi;
            const auto value = packet.substr(colon + 1, end - colon - 1);
            cursor = end < packet.size() ? end + 1 : packet.size();
            if (key == "thread") {
                if (const auto thread = parse_hex_key(value)) {
                    stop_.thread = *thread;
                }
                continue;
            }
            const auto index = parse_hex_key(key);
            if (!index || *index > 0xffffffffu) {
                continue;
            }
            const auto reg_index = static_cast<unsigned>(*index);
            const uint64_t decoded = parse_le_hex(value);
            for (auto& reg : stop_.registers) {
                if (reg.index == reg_index) {
                    reg.value = decoded;
                    reg.hex = value;
                    if (reg.is_pc || (pc_known_ && reg.index == pc_index_)) {
                        stop_.pc = decoded;
                    }
                    break;
                }
            }
        }
    }
    stop_.summary = fmt::format("signal {} at {}", stop_.signal, hex_addr(stop_.pc));
}

void DebugSession::ensure_pc() {
    if (stop_.pc != 0 || !pc_known_) {
        stop_.summary = fmt::format("signal {} at {}", stop_.signal, hex_addr(stop_.pc));
        return;
    }
    const std::string one = roundtrip(fmt::format("p{:x}", pc_index_), 2000, false);
    if (!one.empty() && one.front() != 'E') {
        const std::string decoded = memory_reply(one) ? decode_rle(one) : one;
        stop_.pc = parse_le_hex(decoded);
    }
    if (stop_.pc == 0) {
        const std::string all = roundtrip("g", 3000, false);
        if (!all.empty() && all.front() != 'E') {
            const std::string decoded = memory_reply(all) ? decode_rle(all) : all;
            size_t offset = 0;
            for (const auto& reg : names_) {
                const unsigned bytes = reg.bits == 0 ? 8u : (reg.bits + 7u) / 8u;
                const size_t hex_len = static_cast<size_t>(bytes) * 2u;
                if (offset + hex_len > decoded.size()) {
                    break;
                }
                if (reg.is_pc) {
                    stop_.pc = parse_le_hex(std::string_view(decoded).substr(offset, hex_len));
                    break;
                }
                offset += hex_len;
            }
        }
    }
    for (auto& reg : stop_.registers) {
        if (reg.is_pc || reg.index == pc_index_) {
            reg.value = stop_.pc;
            reg.hex = hex_addr(stop_.pc);
        }
    }
    stop_.summary = fmt::format("signal {} at {}", stop_.signal, hex_addr(stop_.pc));
}

void DebugSession::handshake() {
    rx_.clear();
    rx_pos_ = 0;
    noack_ = false;
    const std::string supported = roundtrip("qSupported:xmlRegisters=i386,arm64", 3000, false);
    log_.append("qSupported ").append(supported.substr(0, std::min<size_t>(supported.size(), 180))).append("\n");
    const std::string ack = roundtrip("QStartNoAckMode", 2000, false);
    if (ack == "OK" || ack.starts_with("OK")) {
        noack_ = true;
    }
    load_register_names();
    const std::string info = roundtrip("qProcessInfo", 2000, false);
    log_.append("qProcessInfo ")
        .append(info.substr(0, std::min<size_t>(info.size(), 240)))
        .append("\n");
    size_t cursor = 0;
    while (cursor < info.size()) {
        const auto semi = info.find(';', cursor);
        const auto field = info.substr(cursor, semi == std::string::npos ? std::string::npos : semi - cursor);
        const auto colon = field.find(':');
        if (colon != std::string::npos) {
            const auto key = field.substr(0, colon);
            const auto value = field.substr(colon + 1);
            if (key == "pid") {
                inferior_pid_ = static_cast<int>(std::strtoul(value.c_str(), nullptr, 16));
            } else if (key == "cputype") {
                const auto cpu = std::strtoul(value.c_str(), nullptr, 16);
                if (cpu == 0x01000007ul || cpu == 7ul) {
                    breakpoint_kind_ = 1;
                } else if (cpu == 0x0100000cul || cpu == 0x0cul) {
                    breakpoint_kind_ = 4;
                }
            }
        }
        if (semi == std::string::npos) {
            break;
        }
        cursor = semi + 1;
    }
    const std::string stop_packet = roundtrip("?", 3000, false);
    refresh_stop(stop_packet);
    ensure_pc();
}

void DebugSession::wait_for_stop() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(io_timeout_ms_);
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw Error("timed out waiting for the debuggee to stop");
        }
        io_timeout_ms_ = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        const std::string packet = read_packet();
        if (packet.empty()) {
            continue;
        }
        const char kind = packet.front();
        if (kind == 'O') {
            if (const auto text = parse_hex_bytes(packet.substr(1))) {
                log_.append(text->begin(), text->end());
            }
            continue;
        }
        if (kind == 'T' || kind == 'S' || kind == 'W' || kind == 'X') {
            refresh_stop(packet);
            if (kind == 'T' || kind == 'S') {
                ensure_pc();
            }
            return;
        }
        refresh_stop(packet);
        return;
    }
}

void DebugSession::cont() {
    io_timeout_ms_ = run_timeout_ms_;
    send_packet("c");
    wait_for_stop();
}

void DebugSession::step() {
    io_timeout_ms_ = run_timeout_ms_ < 10000 ? run_timeout_ms_ : 10000;
    send_packet("s");
    wait_for_stop();
}

bool DebugSession::add_breakpoint(uint64_t address) {
    const auto reply = roundtrip(fmt::format("Z0,{:x},{:x}", address, breakpoint_kind_), 2000, false);
    return reply == "OK" || reply.starts_with("OK");
}

bool DebugSession::remove_breakpoint(uint64_t address) {
    const auto reply = roundtrip(fmt::format("z0,{:x},{:x}", address, breakpoint_kind_), 2000, false);
    return reply == "OK" || reply.starts_with("OK");
}

std::vector<uint8_t> DebugSession::read_memory(uint64_t address, size_t length) {
    if (length > 65536) {
        length = 65536;
    }
    std::vector<uint8_t> out;
    size_t done = 0;
    while (done < length) {
        const size_t chunk = std::min<size_t>(128, length - done);
        const auto reply = roundtrip(fmt::format("m{:x},{:x}", address + done, chunk), 2000, false);
        if (reply.empty() || reply.front() == 'E') {
            throw Error("memory read failed at " + hex_addr(address + done));
        }
        const std::string decoded = memory_reply(reply) ? decode_rle(reply) : reply;
        const auto bytes = parse_hex_bytes(decoded);
        if (!bytes || bytes->empty()) {
            throw Error("memory read returned unexpected data at " + hex_addr(address + done));
        }
        out.insert(out.end(), bytes->begin(), bytes->end());
        done += bytes->size();
        if (bytes->size() < chunk) {
            break;
        }
    }
    return out;
}

std::vector<DebugModule> DebugSession::modules() {
    const auto reply = roundtrip(
        "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true,\"report_load_commands\":false}", 8000, false);
    auto found = modules_from_json(reply);
    if (found.empty()) {
        found = modules_from_scan(reply);
    }
    if (found.empty()) {
        log_.append("module list was empty or not json\n");
        log_.append(reply.substr(0, std::min<size_t>(reply.size(), 400)));
        log_.push_back('\n');
    }
    return found;
}

void DebugSession::shutdown() {
    // Launchd on this Mac does not reap an orphaned zombie. debugserver is the
    // parent, and MachProcess::Kill waits for the child. Signal the process
    // group only after that wait finishes, or the debuggee stays <defunct>.
    const int inferior = inferior_pid_;
    const bool kill_target = !attached_ && inferior > 1;
    if (sock_ >= 0) {
        try {
            write_all(sock_, kill_target ? "$k#6b" : "$D#44");
        } catch (...) {
        }
    }
    if (kill_target) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        while (std::chrono::steady_clock::now() < deadline) {
            if (sock_ >= 0) {
                pollfd fd {};
                fd.fd = sock_;
                fd.events = POLLIN;
                if (::poll(&fd, 1, 20) > 0) {
                    char buffer[1024];
                    const ssize_t n = ::recv(sock_, buffer, sizeof buffer, 0);
                    if (n <= 0) {
                        ::close(sock_);
                        sock_ = -1;
                    }
                }
            } else {
                ::usleep(20 * 1000);
            }
            if (::kill(inferior, 0) == -1 && errno == ESRCH) {
                break;
            }
        }
    }
    if (sock_ >= 0) {
        ::close(sock_);
        sock_ = -1;
    }
    rx_.clear();
    rx_pos_ = 0;
    noack_ = false;
    if (child_pid_ > 0) {
        int status = 0;
        bool reaped = false;
        for (int i = 0; i < 25; ++i) {
            const pid_t got = ::waitpid(child_pid_, &status, WNOHANG);
            if (got == child_pid_ || (got < 0 && errno != EINTR)) {
                reaped = true;
                break;
            }
            ::usleep(20 * 1000);
        }
        if (!reaped) {
            if (!kill_target) {
                ::kill(child_pid_, SIGKILL);
            } else {
                ::kill(-child_pid_, SIGKILL);
                ::kill(child_pid_, SIGKILL);
            }
            for (int i = 0; i < 50; ++i) {
                const pid_t got = ::waitpid(child_pid_, &status, WNOHANG);
                if (got == child_pid_ || (got < 0 && errno != EINTR)) {
                    break;
                }
                ::usleep(20 * 1000);
            }
        }
        child_pid_ = -1;
    }
    if (log_fd_ >= 0) {
        drain_available();
        ::close(log_fd_);
        log_fd_ = -1;
    }
    inferior_pid_ = -1;
    attached_ = false;
}

std::optional<uint64_t> resolve_debug_address(Program* program, DebugSession& session, std::string_view text) {
    if (const auto absolute = parse_address(text)) {
        if (program != nullptr && program->image_size > 0 && *absolute >= program->image_base &&
            *absolute - program->image_base < program->image_size) {
            if (const auto modules = session.modules(); true) {
                if (const auto load = matching_load(*program, modules)) {
                    return runtime_address(*program, *load, *absolute);
                }
            }
        }
        return *absolute;
    }
    if (program == nullptr) {
        return std::nullopt;
    }
    uint64_t static_address = 0;
    bool found = false;
    if (const Function* function = find_function(*program, std::string(text))) {
        static_address = function->address;
        found = true;
    } else if (const Symbol* symbol = find_symbol(*program, text)) {
        static_address = symbol->address;
        found = true;
    }
    if (!found) {
        return std::nullopt;
    }
    const auto modules = session.modules();
    const auto load = matching_load(*program, modules);
    if (!load) {
        return std::nullopt;
    }
    return runtime_address(*program, *load, static_address);
}

bool handle_debug_line(Program* program, DebugSession& session, std::string_view line, std::ostream& out) {
    const std::string text = trim_copy(line);
    if (text.empty()) {
        return true;
    }
    const auto gap = text.find_first_of(" \t");
    const std::string word = gap == std::string::npos ? text : text.substr(0, gap);
    const std::string rest = gap == std::string::npos ? std::string() : trim_copy(std::string_view(text).substr(gap));
    if (word == "q" || word == "quit") {
        return false;
    }
    if (word == "help" || word == "?") {
        out << "c              continue\n"
            << "s              step one instruction\n"
            << "n              step over a call\n"
            << "b <addr|name>  breakpoint at a runtime address, or a static symbol\n"
            << "d <addr|name>  remove that breakpoint\n"
            << "r              registers from the last stop\n"
            << "m <addr> [n]   read memory\n"
            << "mods           loaded modules\n"
            << "dis            instruction at the static cursor, when a program is open\n"
            << "q              stop debugging\n";
        return true;
    }
    if (word == "c" || word == "cont" || word == "continue") {
        session.cont();
        print_stop(out, session.stop());
        return true;
    }
    if (word == "s" || word == "si" || word == "step") {
        session.step();
        print_stop(out, session.stop());
        return true;
    }
    if (word == "n" || word == "next") {
        const uint64_t pc = session.stop().pc;
        bool stepped = false;
        if (program != nullptr && program->arch != Arch::Unknown && pc != 0) {
            const auto bytes = session.read_memory(pc, 16);
            if (const auto insn = disassemble_one(program->arch, pc, bytes.data(), bytes.size())) {
                if (insn->flow == Flow::Call && insn->size > 0) {
                    const uint64_t ret = pc + insn->size;
                    const bool planted = session.add_breakpoint(ret);
                    session.cont();
                    if (planted) {
                        session.remove_breakpoint(ret);
                    }
                    stepped = true;
                }
            }
        }
        if (!stepped) {
            session.step();
        }
        print_stop(out, session.stop());
        return true;
    }
    if (word == "b" || word == "break") {
        const auto address = resolve_debug_address(program, session, rest);
        if (!address) {
            out << "breakpoint needs an address or a known symbol\n";
            return true;
        }
        if (!session.add_breakpoint(*address)) {
            out << "breakpoint refused at " << hex_addr(*address) << "\n";
            return true;
        }
        out << "breakpoint at " << hex_addr(*address) << "\n";
        return true;
    }
    if (word == "d" || word == "delete" || word == "clear") {
        const auto address = resolve_debug_address(program, session, rest);
        if (!address) {
            out << "delete needs an address or a known symbol\n";
            return true;
        }
        out << (session.remove_breakpoint(*address) ? "removed " : "could not remove ") << hex_addr(*address) << "\n";
        return true;
    }
    if (word == "r" || word == "regs") {
        print_stop(out, session.stop());
        return true;
    }
    if (word == "m" || word == "x" || word == "mem") {
        std::string addr_text = rest;
        size_t length = 64;
        const auto split = rest.find_first_of(" \t");
        if (split != std::string::npos) {
            addr_text = rest.substr(0, split);
            if (const auto parsed = parse_address(trim_copy(std::string_view(rest).substr(split)))) {
                length = static_cast<size_t>(*parsed);
            }
        }
        const auto address = resolve_debug_address(program, session, addr_text);
        if (!address) {
            out << "memory read needs an address\n";
            return true;
        }
        const auto bytes = session.read_memory(*address, length);
        print_bytes(out, *address, bytes);
        return true;
    }
    if (word == "mods" || word == "modules") {
        const auto modules = session.modules();
        if (modules.empty()) {
            out << "no modules\n";
            return true;
        }
        for (const auto& module : modules) {
            out << hex_addr(module.load_address) << "  " << module.path << "\n";
        }
        return true;
    }
    if (word == "dis" || word == "disasm") {
        if (program == nullptr) {
            out << "no program is open\n";
            return true;
        }
        const auto modules = session.modules();
        const auto load = matching_load(*program, modules);
        if (!load) {
            out << "the open program is not in the module list\n";
            return true;
        }
        const uint64_t static_va = program->image_base + (session.stop().pc - *load);
        out << "static " << hex_addr(static_va) << "\n";
        if (const Instruction* insn = find_insn(*program, static_va)) {
            out << insn->mnemonic << " " << insn->op_str << "\n";
        } else {
            out << render_disasm(*program, hex_addr(static_va), 8);
        }
        return true;
    }
    out << "unknown debugger command. help lists them.\n";
    return true;
}

void debug_repl(Program* program, DebugSession& session, std::istream& in, std::ostream& out) {
    out << "fathom debug. help lists commands.\n";
    print_stop(out, session.stop());
    std::string line;
    while (std::getline(in, line)) {
        try {
            if (!handle_debug_line(program, session, line, out)) {
                return;
            }
        } catch (const Error& error) {
            out << "error: " << error.what() << "\n";
        }
    }
}

}  // namespace fathom
