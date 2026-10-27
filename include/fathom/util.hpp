#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fathom {

std::string hex_addr(uint64_t value);
std::optional<uint64_t> parse_address(std::string_view text);
std::string base_name(std::string_view path);
bool iequals(std::string_view a, std::string_view b);
std::string json_escape(std::string_view text);
std::string dot_escape(std::string_view text);
std::optional<std::vector<uint8_t>> parse_hex_bytes(std::string_view text);
std::optional<std::vector<uint8_t>> decode_base64(std::string_view text);
double shannon_entropy(const uint8_t* data, size_t size);
std::optional<uint64_t> checked_add(uint64_t a, uint64_t b);

}  // namespace fathom
