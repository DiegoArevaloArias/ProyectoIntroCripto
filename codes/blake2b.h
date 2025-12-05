#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <bits/stdc++.h>

using u64 = uint64_t;
using u8  = uint8_t;

std::vector<u8> blake2b(std::vector<u8> out, size_t outlen,
            std::vector<u8> in, size_t inlen,
            std::vector<u8> key = {}, size_t keylen = 0,
            std::vector<u8> salt = {}, std::vector<u8> person = {});

#endif
