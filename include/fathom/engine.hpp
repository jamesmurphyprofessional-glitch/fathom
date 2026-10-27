#pragma once

#include "fathom/program.hpp"

#include <string>
#include <string_view>

namespace fathom {

Program load_program(const std::string& path, const Options& options = {});
void analyze(Program& program, const Options& options = {});
void disassemble_program(Program& program, const Options& options = {});

std::optional<Instruction> disassemble_one(Arch arch, uint64_t address,
                                           const uint8_t* data, size_t size);

const Function* find_function(const Program& program, const std::string& name_or_addr);
const Symbol* find_symbol(const Program& program, std::string_view name);

std::string render_summary(const Program& program);
std::string render_triage(const Program& program);
std::string render_functions(const Program& program);
std::string render_strings(const Program& program, size_t limit);
std::string render_disasm(const Program& program, const std::string& func, size_t limit);
std::string render_decompile(const Program& program, const std::string& func);
std::string render_xrefs(const Program& program, const std::string& target);
std::string render_cfg(const Program& program, const std::string& func);
std::string render_dot(const Program& program, const std::string& func);
std::string render_objects(const Program& program);
std::string render_hex(const Program& program, uint64_t origin, bool by_va, size_t length);
std::string render_find_text(const Program& program, const std::string& needle);
std::string render_find_bytes(const Program& program, const std::vector<uint8_t>& needle);
std::string render_json(const Program& program);

}  // namespace fathom
