#ifndef BLAKE2B_H
#define BLAKE2B_H
#include <cstdint>
#include <cstddef>

int blake2b(unsigned char *out, size_t outlen,
            const unsigned char *in, size_t inlen,
            const unsigned char *key = nullptr, size_t keylen = 0,
            const unsigned char *salt = nullptr,
            const unsigned char *person = nullptr);

#endif
