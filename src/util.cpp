#include "fathom/util.hpp"

#include <fmt/format.h>

#include <cctype>
#include <cmath>

namespace fathom {
namespace {

int hex_value(char c) {
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

}  // namespace

std::string hex_addr(uint64_t value) {
    return fmt::format("0x{:x}", value);
}

std::optional<uint64_t> parse_address(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
        if (text.empty()) {
            return std::nullopt;
        }
    }
    uint64_t value = 0;
    for (char c : text) {
        int digit = hex_value(c);
        if (digit < 0 || digit >= base) {
            return std::nullopt;
        }
        if (value > (UINT64_MAX - static_cast<uint64_t>(digit)) / static_cast<uint64_t>(base)) {
            return std::nullopt;
        }
        value = value * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
    }
    return value;
}

std::string base_name(std::string_view path) {
    const auto pos = path.find_last_of("/\\");
    if (pos == std::string_view::npos) {
        return std::string(path);
    }
    return std::string(path.substr(pos + 1));
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        const unsigned char ca = static_cast<unsigned char>(a[i]);
        const unsigned char cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb)) {
            return false;
        }
    }
    return true;
}

std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (unsigned char c : text) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                constexpr char kDigits[] = "0123456789abcdef";
                out += "\\u00";
                out.push_back(kDigits[c >> 4]);
                out.push_back(kDigits[c & 0xf]);
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return out;
}

std::string dot_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::optional<std::vector<uint8_t>> parse_hex_bytes(std::string_view text) {
    std::string compact;
    compact.reserve(text.size());
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == ':' || c == '-') {
            continue;
        }
        compact.push_back(c);
    }
    if (compact.empty() || (compact.size() % 2) != 0) {
        return std::nullopt;
    }
    std::vector<uint8_t> out;
    out.reserve(compact.size() / 2);
    for (size_t i = 0; i < compact.size(); i += 2) {
        const int hi = hex_value(compact[i]);
        const int lo = hex_value(compact[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::optional<std::vector<uint8_t>> decode_base64(std::string_view text) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        return -1;
    };
    std::vector<uint8_t> out;
    int val = 0;
    int valb = -8;
    for (char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') {
            continue;
        }
        const int d = value(c);
        if (d < 0) {
            return std::nullopt;
        }
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xff));
            valb -= 8;
        }
    }
    return out;
}

double shannon_entropy(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) {
        return 0;
    }
    uint64_t hist[256] = {};
    for (size_t i = 0; i < size; ++i) {
        hist[data[i]] += 1;
    }
    double entropy = 0;
    const double n = static_cast<double>(size);
    for (uint64_t count : hist) {
        if (count == 0) {
            continue;
        }
        const double p = static_cast<double>(count) / n;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::optional<uint64_t> checked_add(uint64_t a, uint64_t b) {
    if (a > UINT64_MAX - b) {
        return std::nullopt;
    }
    return a + b;
}

}  // namespace fathom
