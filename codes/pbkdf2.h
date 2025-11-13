#ifndef PBKDF2
#define PBKDF2

#include <string>
#include <vector>
#include <cstddef>

// Declaración de la función PBKDF2-SHA256
// Retorna la clave derivada como vector<unsigned char> (bytes).
std::vector<unsigned char> pbkdf2_sha256_bytes(
    const std::string &password,
    const std::vector<unsigned char> &salt,
    int iterations,
    std::size_t key_len = 32
);

std::vector<unsigned char> generarSalt(std::size_t len);
std::string binAHex(const std::vector<unsigned char> &data);

#endif
