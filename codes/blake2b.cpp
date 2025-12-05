#include "blake2b.h"
#include <bits/stdc++.h>

using namespace std;

using u64 = uint64_t;
using u8  = uint8_t;

static const u64 IV[8] = {
  0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
  0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
  0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
  0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const uint8_t SIGMA[12][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
  {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
  { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
  { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
  {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
  {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
  { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

inline u64 rotr(u64 x, unsigned r) { return (x >> r) | (x << (64 - r)); }

inline void G(u64 &a, u64 &b, u64 &c, u64 &d, u64 x, u64 y) {
  a = a + b + x;
  d = rotr(d ^ a, 32);
  c = c + d;
  b = rotr(b ^ c, 24);
  a = a + b + y;
  d = rotr(d ^ a, 16);
  c = c + d;
  b = rotr(b ^ c, 63);
}

void compress(std::vector<u64> &h, std::vector<u8> block, uint64_t t_low, uint64_t t_high, bool last) {
  u64 v[16];
  u64 m[16];

  for (int i = 0; i < 16; ++i) {
    u64 w = 0;
    for (int j = 0; j < 8; ++j) w |= (u64)block[i*8 + j] << (8*j);
    m[i] = w;
  }
  for (int i = 0; i < 8; ++i) v[i] = h[i];
  for (int i = 0; i < 8; ++i) v[i+8] = IV[i];

  v[12] ^= t_low;
  v[13] ^= t_high;
  if (last) v[14] = ~v[14];

  for (int r = 0; r < 12; ++r) {
    const uint8_t *s = SIGMA[r];
    G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
    G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
    G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
    G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);

    G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
    G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
    G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
    G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; ++i) h[i] = h[i] ^ v[i] ^ v[i+8];
}

inline void store64(u8 out[8], u64 w) {
  for (int i = 0; i < 8; ++i) out[i] = (u8)((w >> (8*i)) & 0xFF);
}

void copyy (std::vector<u8> &a, std::vector<u8> &b, int x, int y, int z) {
  for (int i = 0; i < z; ++i) a[i + x] = b[i + y];
}

std::vector<u8> blake2b(std::vector<u8> out, size_t outlen,
            std::vector<u8> in, size_t inlen,
            std::vector<u8> key, size_t keylen,
            std::vector<u8> salt, std::vector<u8> person) {

  std::vector<u8> param(64, 0);
  param[0] = (uint8_t)outlen;
  param[1] = (uint8_t)keylen;
  param[2] = 1;
  param[3] = 1;

  if (salt.size()) copyy (param, salt, 32, 0, 16);
  if (person.size()) copyy (param, person, 48, 0, 16);

  std::vector <u64> h(8);
  for (int i = 0; i < 8; ++i) h[i] = IV[i];

  for (int i = 0; i < 8; ++i) {
    u64 w = 0;
    for (int j = 0; j < 8; ++j) w |= (u64)param[i*8 + j] << (8*j);
    h[i] ^= w;
  }

  size_t offset = 0;
  uint64_t t_low = 0, t_high = 0;
  std::vector<u8> block(128, 0);
  bool last = false;

  auto increment_t = [&](size_t inc) {
    uint64_t prev = t_low;
    t_low += inc;
    if (t_low < prev) ++t_high;
  };

  if (key.size() && keylen > 0) {
    block = vector<u8> (128,0);
    copyy (block, key, 0, 0, keylen);
    increment_t(128);
    if (inlen == 0) last = true;
    compress(h, block, t_low, t_high, last);
  }

  while (offset + 128 <= inlen) {
    copyy ( block, in, 0, offset, 128 );
    increment_t(128);
    compress(h, block, t_low, t_high, false);
    offset += 128;
  }

  size_t left = inlen - offset;
  block = vector<u8> (128,0);
  if (left) copyy (block, in, 0, offset, left);

  increment_t(left ? left : 128);
  last = true;
  compress(h, block, t_low, t_high, last);

  uint8_t buffer[64];
  for (int i = 0; i < 8; ++i) store64(buffer + i*8, h[i]);
  for (int i = 0; i < outlen; ++i) out[i] = buffer[i];
  return out;
}
