#include "argon2_simplified.h"
#include "blake2b.h"
#include <bits/stdc++.h>

using namespace std;

static std::string to_hex(const std::vector<uint8_t> &v) {
  std::ostringstream os;
  for (auto b: v) os << std::hex << std::setw(2) << std::setfill('0') <<
  (int)b;
  return os.str();
}

void hash_blake2b (string w) {
  size_t inlen = w.size();
  vector <u8> input(inlen);
  for (int i = 0; i < inlen; ++i) input[i] = (uint8_t) w[i];

  vector <u8> out(64);

  auto tag = blake2b(out, 64,
          input, inlen);

  std::cout << to_hex(tag) << '\n';
}

void hash_argon2 (string w) {
  std::string pwd = w;
  std::vector<uint8_t> salt = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,0x01,
  0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
  Argon2Params p;
  auto tag = argon2_hash(pwd, salt, p);
  std::cout << to_hex(tag) << endl;
}

int main(int argc, char **argv) {

  cout << "BLAKE 2B --------------- \n";

  hash_blake2b ("hola");
  hash_blake2b ("hols");
  hash_blake2b ("hola");
  hash_blake2b ("holaaaaa");

  cout << "ARGON 2 ------------------\n";

  hash_argon2 ("mypass123");
  hash_argon2 ("mypass1234");
  hash_argon2 ("mypess123");
  hash_argon2 ("mypass123");

  return 0;
}
