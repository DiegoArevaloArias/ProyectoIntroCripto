#include <iostream>
#include <vector>
#include <iomanip>
#include "argon2_simplified.h"

static std::string to_hex(const std::vector<uint8_t> &v) {
  std::ostringstream os;
  for (auto b: v) os << std::hex << std::setw(2) << std::setfill('0') <<
  (int)b;
  return os.str();
}
int main(int argc, char **argv) {
  std::string pwd = "password123";
  std::vector<uint8_t> salt = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,0x01,
  0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
  Argon2Params p; p.time_cost = 2; p.mem_kib = 32768; p.parallelism = 2;
  p.tag_len = 32;
  auto tag = argon2_hash(pwd, salt, p);
  std::cout << "Argon2-simplified tag: " << to_hex(tag) << std::endl;
  return 0;
}
