#include "argon2_simplified.h"
#include "blake2b.h"
#include <cstring>
#include <stdexcept>
#include <iostream>

static const size_t BLOCK_BYTES = 1024;
using u8 = uint8_t;
struct Block {
  u8 v[BLOCK_BYTES];
};

static std::vector<u8> blake2b_vec(const std::vector<u8> &in, size_t outlen) {
  std::vector<u8> out(outlen);
  blake2b(out.data(), outlen, in.data(), in.size(), nullptr, 0, nullptr,
  nullptr);
  return out;
}

static std::vector<u8> compute_H0(const std::string &pwd, const std::vector<u8>
&salt, const Argon2Params &p) {
  std::vector<u8> buf;
  auto push32 = [&](uint32_t x){ for (int i=0;i<4;++i) buf.push_back((u8)
  ((x>>(8*i))&0xFF)); };
  push32(p.time_cost); push32(p.mem_kib); push32(p.parallelism);
  push32(p.tag_len);
  uint32_t plen = (uint32_t)pwd.size(); push32(plen);
  buf.insert(buf.end(), pwd.begin(), pwd.end());
  uint32_t slen = (uint32_t)salt.size(); push32(slen);
  buf.insert(buf.end(), salt.begin(), salt.end());
  return blake2b_vec(buf, 64);
}

static void xor_block(Block &out, const Block &a, const Block &b) {
  for (size_t i=0;i<BLOCK_BYTES;++i) out.v[i] = a.v[i] ^ b.v[i];
}

static Block G_function(const Block &X, const Block &Y) {
  std::vector<u8> in;
  in.reserve(BLOCK_BYTES*2);
  in.insert(in.end(), X.v, X.v + BLOCK_BYTES);
  in.insert(in.end(), Y.v, Y.v + BLOCK_BYTES);
  Block out;

  size_t produced = 0;
  uint64_t counter = 0;

  while (produced < BLOCK_BYTES) {
    std::vector<u8> tmp = in;
    for (int i=0;i<8;++i)
      tmp.push_back((u8)((counter >> (8*i)) & 0xFF));
    size_t need = std::min<size_t>(64, BLOCK_BYTES - produced);
    std::vector<u8> h = blake2b_vec(tmp, 64);
    memcpy(out.v + produced, h.data(), need);
    produced += need;
    ++counter;
  }
  for (size_t i=0;i<BLOCK_BYTES;++i) out.v[i] ^= (X.v[i] ^ Y.v[i]);
  return out;
}

static uint64_t block_prng64(const Block &b, uint64_t ctr) {
  std::vector<u8> in;
  in.insert(in.end(), b.v, b.v + BLOCK_BYTES);
  for (int i=0;i<8;++i) in.push_back((u8)((ctr >> (8*i)) & 0xFF));
  std::vector<u8> h = blake2b_vec(in, 8);
  uint64_t v = 0;
  for (int i=0;i<8;++i) v |= ((uint64_t)h[i]) << (8*i);
  return v;
  }
  std::vector<uint8_t> argon2_hash(const std::string &password, const
  std::vector<uint8_t> &salt, const Argon2Params &params) {
  if (salt.size() < 8) throw std::invalid_argument("salt too small");
  if (params.parallelism == 0) throw std::invalid_argument("parallelism mustbe >=1");
  std::vector<u8> H0 = compute_H0(password, salt, params);
  size_t m_kib = params.mem_kib;
  size_t total_blocks = (m_kib * 1024) / BLOCK_BYTES;
  if (total_blocks < params.parallelism * 2) total_blocks = params.parallelism * 2;
  size_t q = total_blocks / params.parallelism;
  std::vector<std::vector<Block>> lanes(params.parallelism, std::vector<Block>(q));
  for (uint32_t lane = 0; lane < params.parallelism; ++lane) {
    for (int idx = 0; idx < 2; ++idx) {
      std::vector<u8> in = H0;
      for (int i=0;i<4;++i) in.push_back((u8)((lane >> (8*i)) & 0xFF));
      for (int i=0;i<4;++i) in.push_back((u8)((idx >> (8*i)) & 0xFF));
      Block B;
      size_t produced = 0;
      uint64_t ctr = 0;
      while (produced < BLOCK_BYTES) {
        std::vector<u8> tmp = in;
        for (int i=0;i<8;++i) tmp.push_back((u8)((ctr >> (8*i)) &
        0xFF));
        std::vector<u8> h = blake2b_vec(tmp, 64);
        size_t need = std::min<size_t>(64, BLOCK_BYTES - produced);
        memcpy(B.v + produced, h.data(), need);
        produced += need; ++ctr;
      }
      lanes[lane][idx] = B;
    }
  }

  for (uint32_t pass = 0; pass < params.time_cost; ++pass) {
    for (size_t lane = 0; lane < params.parallelism; ++lane) {
    for (size_t idx = 0; idx < q; ++idx) {
        if (pass == 0 && idx < 2) continue;
        const Block &X = (idx == 0) ? lanes[lane][q-1] : lanes[lane]
        [idx-1];


        uint64_t rnd = block_prng64(X, pass + idx);
        size_t ref_lane = rnd % params.parallelism;
        size_t ref_idx = (rnd / params.parallelism) % q;

        if (pass == 0 && idx < q/2) {
          std::vector<u8> seed = H0;
          for (int i=0;i<4;++i) seed.push_back((u8)((pass >> (8*i)) &
          0xFF));
          for (int i=0;i<4;++i) seed.push_back((u8)((lane >> (8*i)) &
          0xFF));
          for (int i=0;i<4;++i) seed.push_back((u8)((idx >> (8*i)) &
          0xFF));
          std::vector<u8> h = blake2b_vec(seed, 8);
          uint64_t v=0; for (int i=0;i<8;++i) v |= ((uint64_t)h[i]) << (8*i);
          ref_lane = v % params.parallelism;
          ref_idx = (v / params.parallelism) % q;
        }
        const Block &Y = lanes[ref_lane][ref_idx];
        Block Z = G_function(X, Y);
        lanes[lane][idx] = Z;
      }
    }
  }
  Block C; memset(C.v, 0, BLOCK_BYTES);
  for (size_t lane = 0; lane < params.parallelism; ++lane) {
    const Block &last = lanes[lane][q-1];
    for (size_t i=0;i<BLOCK_BYTES;++i) C.v[i] ^= last.v[i];
  }
  std::vector<u8> cvec(C.v, C.v + BLOCK_BYTES);
  std::vector<u8> tag = blake2b_vec(cvec, params.tag_len);
  return tag;
}
