#ifndef ARGON2_SIMPLIFIED_H
#define ARGON2_SIMPLIFIED_H
#include <cstdint>
#include <vector>
#include <string>
struct Argon2Params {
  uint32_t time_cost = 3; // t
  uint32_t mem_kib = 65536; // m in KiB
  uint32_t parallelism = 1; // p
  uint32_t tag_len = 32; // output tag length in bytes
};

std::vector<uint8_t> argon2_hash(const std::string &password, const
std::vector<uint8_t> &salt, const Argon2Params &params);
#endif
