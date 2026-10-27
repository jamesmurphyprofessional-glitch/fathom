#include "fathom/retsync.hpp"

#include "fathom/util.hpp"

#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <string_view>

namespace fathom {
namespace {

constexpr size_t kMaxLine = 1024 * 1024;
constexpr size_t kMaxComments = 10000;
constexpr size_t kMaxCommentText = 8192;

bool loopback_host(std::string_view host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1";
}

// The LLDB plugin runs every raw reply line as a debugger command. The sample
// name is chosen by whoever produced the file, so the reply keeps only a
// single token and drops newlines and quotes.
std::string idb_token(std::string_view path) {
    const std::string name = base_name(path);
    std::string out;
    for (unsigned char c : name) {
        if (out.size() == 80) {
            break;
        }
        if (std::isalnum(c) || c == '.' || c == '_' || c == '-') {
            out.push_back(static_cast<char>(c));
        }
    }
    if (out.empty()) {
        return "fathom";
    }
    return out;
}

bool loopback_peer(const sockaddr_storage& address) {
    if (address.ss_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&address);
        const uint32_t ip = ntohl(v4->sin_addr.s_addr);
        return (ip >> 24) == 127;
    }
    if (address.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&address);
        return IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr);
    }
    return false;
}

void write_all(int fd, std::string_view bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
        const ssize_t n = ::send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw Error("ret-sync write failed: " + std::string(std::strerror(errno)));
        }
        if (n == 0) {
            throw Error("ret-sync write returned no bytes");
        }
        sent += static_cast<size_t>(n);
    }
}

std::optional<uint64_t> json_u64(const nlohmann::json& object, const char* key) {
    if (!object.contains(key)) {
        return std::nullopt;
    }
    const auto& value = object[key];
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

std::string clip(std::string text, size_t max_chars) {
    if (text.size() > max_chars) {
        text.resize(max_chars);
    }
    return text;
}

std::string json_string(const nlohmann::json& object, const char* key) {
    if (!object.contains(key) || !object[key].is_string()) {
        return {};
    }
    return object[key].get<std::string>();
}

}  // namespace

uint64_t rebase_to_static(uint64_t preferred_base, uint64_t runtime_base, uint64_t runtime_pc) {
    return preferred_base + (runtime_pc - runtime_base);
}

RetSyncServer::RetSyncServer(Program& program) : program_(program) {}

RetSyncServer::~RetSyncServer() {
    try {
        stop();
    } catch (...) {
    }
}

void RetSyncServer::start(const std::string& host, uint16_t port, bool allow_remote) {
    stop();
    if (host.empty()) {
        throw Error("ret-sync needs a bind address");
    }
    if (!allow_remote && !loopback_host(host)) {
        throw Error("ret-sync refuses " + host + " without --allow-remote; the listener is unauthenticated");
    }
    const std::string bind_host = host == "localhost" ? "127.0.0.1" : host;
    if (!allow_remote && bind_host != "127.0.0.1") {
        throw Error("ret-sync loopback mode binds 127.0.0.1");
    }

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw Error("cannot open a ret-sync socket");
    }
    const int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, bind_host.c_str(), &address.sin_addr) != 1) {
        ::close(fd);
        throw Error("ret-sync cannot parse the bind address " + bind_host);
    }
    if (!allow_remote && ntohl(address.sin_addr.s_addr) >> 24 != 127) {
        ::close(fd);
        throw Error("ret-sync refuses a non-loopback bind without --allow-remote");
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0) {
        const std::string message = std::strerror(errno);
        ::close(fd);
        throw Error("ret-sync cannot bind " + bind_host + ":" + std::to_string(port) + ": " + message);
    }
    if (::listen(fd, 1) != 0) {
        const std::string message = std::strerror(errno);
        ::close(fd);
        throw Error("ret-sync cannot listen: " + message);
    }
    sockaddr_in actual {};
    socklen_t actual_len = sizeof actual;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&actual), &actual_len) != 0) {
        ::close(fd);
        throw Error("ret-sync cannot read its listen port");
    }

    {
        std::lock_guard<std::mutex> lock(mu_);
        listen_fd_ = fd;
        host_ = bind_host;
        port_ = ntohs(actual.sin_port);
        allow_remote_ = allow_remote;
        stop_ = false;
        state_ = {};
        location_generation_ = 0;
    }
    thread_ = std::thread([this] { thread_main(); });
}

void RetSyncServer::stop() {
    int listen_fd = -1;
    int client_fd = -1;
    {
        std::lock_guard<std::mutex> lock(mu_);
        stop_ = true;
        listen_fd = listen_fd_;
        listen_fd_ = -1;
    }
    if (listen_fd >= 0) {
        ::shutdown(listen_fd, SHUT_RDWR);
    }
    {
        std::lock_guard<std::mutex> write(write_mu_);
        std::lock_guard<std::mutex> lock(mu_);
        client_fd = client_fd_;
        client_fd_ = -1;
    }
    if (client_fd >= 0) {
        ::shutdown(client_fd, SHUT_RDWR);
        ::close(client_fd);
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    if (listen_fd >= 0) {
        ::close(listen_fd);
    }
    cv_.notify_all();
}

SyncState RetSyncServer::state() const {
    std::lock_guard<std::mutex> lock(mu_);
    return state_;
}

bool RetSyncServer::wait_location(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mu_);
    return cv_.wait_for(lock, timeout, [this] { return state_.location_valid; });
}

void RetSyncServer::send_debugger_command(const std::string& line) {
    if (line.empty() || line.size() > 4096 || line.find('\0') != std::string::npos) {
        throw Error("debugger command must be 1 to 4096 bytes");
    }
    if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) {
        throw Error("debugger command must be a single line");
    }
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(mu_);
        fd = client_fd_;
    }
    if (fd < 0) {
        throw Error("no ret-sync debugger is connected");
    }
    const std::string wire = line + "\n";
    std::lock_guard<std::mutex> write(write_mu_);
    write_all(fd, wire);
}

void RetSyncServer::thread_main() {
    while (true) {
        int listen_fd = -1;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (stop_) {
                return;
            }
            listen_fd = listen_fd_;
        }
        if (listen_fd < 0) {
            return;
        }
        pollfd wait_fd {};
        wait_fd.fd = listen_fd;
        wait_fd.events = POLLIN;
        const int rc = ::poll(&wait_fd, 1, 200);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::lock_guard<std::mutex> lock(mu_);
            state_.last_error = "ret-sync poll failed";
            return;
        }
        if (rc == 0 || (wait_fd.revents & POLLIN) == 0) {
            continue;
        }
        sockaddr_storage peer {};
        socklen_t peer_len = sizeof peer;
        const int client = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (client < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) {
                continue;
            }
            std::lock_guard<std::mutex> lock(mu_);
            if (!stop_) {
                state_.last_error = "ret-sync accept failed";
            }
            continue;
        }
        bool remote_ok = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            remote_ok = allow_remote_;
        }
        if (!remote_ok && !loopback_peer(peer)) {
            ::close(client);
            std::lock_guard<std::mutex> lock(mu_);
            state_.last_error = "rejected a non-loopback ret-sync peer";
            continue;
        }
        const int one = 1;
        ::setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        handle_client(client);
    }
}

void RetSyncServer::handle_client(int client) {
    {
        std::lock_guard<std::mutex> write(write_mu_);
        std::lock_guard<std::mutex> lock(mu_);
        if (client_fd_ >= 0) {
            ::shutdown(client_fd_, SHUT_RDWR);
            ::close(client_fd_);
        }
        client_fd_ = client;
        state_.connected = true;
        state_.last_error.clear();
    }
    std::string pending;
    while (true) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (stop_ || client_fd_ != client) {
                break;
            }
        }
        pollfd wait_fd {};
        wait_fd.fd = client;
        wait_fd.events = POLLIN;
        const int rc = ::poll(&wait_fd, 1, 200);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (rc == 0) {
            continue;
        }
        char buffer[8192];
        const ssize_t n = ::recv(client, buffer, sizeof buffer, 0);
        if (n <= 0) {
            break;
        }
        if (pending.size() + static_cast<size_t>(n) > kMaxLine) {
            std::lock_guard<std::mutex> lock(mu_);
            state_.last_error = "ret-sync peer exceeded the 1 MiB message cap";
            break;
        }
        pending.append(buffer, static_cast<size_t>(n));
        size_t start = 0;
        for (size_t i = 0; i < pending.size(); ++i) {
            if (pending[i] != '\n') {
                continue;
            }
            std::string line = pending.substr(start, i - start);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            start = i + 1;
            if (!line.empty()) {
                handle_line(line, client);
            }
        }
        pending.erase(0, start);
    }
    {
        std::lock_guard<std::mutex> write(write_mu_);
        std::lock_guard<std::mutex> lock(mu_);
        if (client_fd_ == client) {
            client_fd_ = -1;
            ::close(client);
        }
        state_.connected = false;
    }
}

void RetSyncServer::handle_line(const std::string& line, int client) {
    constexpr std::string_view kNotice = "[notice]";
    constexpr std::string_view kSync = "[sync]";
    std::string_view body;
    if (line.starts_with(kNotice)) {
        body = std::string_view(line).substr(kNotice.size());
    } else if (line.starts_with(kSync)) {
        body = std::string_view(line).substr(kSync.size());
    } else {
        std::lock_guard<std::mutex> lock(mu_);
        state_.messages += 1;
        state_.last_error = "ignored a line that is not a ret-sync message";
        return;
    }

    nlohmann::json message;
    try {
        message = nlohmann::json::parse(body);
    } catch (const std::exception&) {
        std::lock_guard<std::mutex> lock(mu_);
        state_.messages += 1;
        state_.last_error = "ret-sync message was not json";
        return;
    }
    if (!message.is_object() || !message.contains("type") || !message["type"].is_string()) {
        std::lock_guard<std::mutex> lock(mu_);
        state_.messages += 1;
        state_.last_error = "ret-sync message has no type";
        return;
    }
    const std::string type = message["type"].get<std::string>();

    auto locate = [&](SyncState& state) {
        const auto base = json_u64(message, "base");
        const auto offset = json_u64(message, "offset");
        if (!base || !offset) {
            return;
        }
        state.runtime_base = *base;
        state.runtime_pc = *offset;
        state.static_va = rebase_to_static(program_.image_base, *base, *offset);
        state.location_valid = true;
        location_generation_ += 1;
    };

    std::string reply;
    {
        std::lock_guard<std::mutex> lock(mu_);
        state_.messages += 1;
        state_.last_error.clear();
        if (type == "new_dbg") {
            state_.connected = true;
            state_.dialect = clip(json_string(message, "dialect"), 64);
            state_.identity = clip(json_string(message, "msg"), 512);
        } else if (type == "dbg_quit") {
            state_.connected = false;
            state_.identity = clip(json_string(message, "msg"), 512);
        } else if (type == "module") {
            state_.module_path = clip(json_string(message, "path"), 4096);
            if (!program_.path.empty() && !state_.module_path.empty() &&
                !iequals(base_name(program_.path), base_name(state_.module_path))) {
                state_.last_error = "ret-sync module name does not match the open program";
            }
        } else if (type == "loc") {
            locate(state_);
        } else if (type == "cmt" || type == "fcmt" || type == "cmd" || type == "bc") {
            locate(state_);
            if (state_.comments.size() < kMaxComments) {
                Comment comment;
                comment.address = state_.static_va;
                comment.source = "ret-sync";
                if (type == "fcmt") {
                    comment.source = "ret-sync-function";
                    for (const auto& function : program_.functions) {
                        if (state_.static_va >= function.address && state_.static_va < function.end) {
                            comment.address = function.address;
                            break;
                        }
                    }
                }
                std::string text = json_string(message, "msg");
                if (type == "cmd") {
                    if (const auto decoded = decode_base64(text)) {
                        text.assign(decoded->begin(), decoded->end());
                    }
                    comment.source = "ret-sync-output";
                } else if (type == "bc") {
                    text = "color " + text;
                    comment.source = "ret-sync-color";
                }
                comment.text = clip(std::move(text), kMaxCommentText);
                state_.comments.push_back(std::move(comment));
            }
        } else if (type == "rcmt") {
            locate(state_);
            const uint64_t address = state_.static_va;
            std::erase_if(state_.comments, [address](const Comment& comment) { return comment.address == address; });
        } else if (type == "idb_list") {
            reply = "> currently connected idb(s):\n    [0] " + idb_token(program_.path) + "\n";
        } else if (type == "idb_n") {
            const auto idb = json_string(message, "idb");
            if (idb == "0") {
                reply = "> active idb is now \"" + idb_token(program_.path) + "\" (0)\n";
            } else {
                reply = "> idb_n error: index is invalid (see idblist)\n";
            }
        } else if (type == "sync_mode" || type == "dbg_err" || type == "rln" || type == "rrln") {
            state_.last_error.clear();
        } else {
            state_.last_error = "ignored ret-sync type " + clip(type, 64);
        }
    }
    if (!reply.empty()) {
        try {
            std::lock_guard<std::mutex> write(write_mu_);
            write_all(client, reply);
        } catch (const Error& error) {
            std::lock_guard<std::mutex> lock(mu_);
            state_.last_error = error.what();
        }
    }
    cv_.notify_all();
}

}  // namespace fathom
