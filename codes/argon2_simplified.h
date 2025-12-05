#ifndef ARGON2_SIMPLIFIED_H
#define ARGON2_SIMPLIFIED_H
#include <bits/stdc++.h>

  struct Argon2Params {
    uint32_t time_cost = 3;
    uint32_t mem_kib = 20;
    uint32_t parallelism = 4;
    uint32_t tag_len = 64;
  };

  std::vector<uint8_t> argon2_hash(const std::string &password, const
                                  std::vector<uint8_t> &salt, const Argon2Params &params);
#endif
