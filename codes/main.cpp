// main.cpp
#include <iostream>
#include <string>
#include "pbkdf2.h"
#include "AES256Implementacion.h"

using namespace std;

int main() {
    // Parámetros
    string password = "MiPasswordSegura123!";
    int iterations = 100000;
    size_t key_len = 32;

    // 1) generar salt (aleatorio) — guardarlo junto al ciphertext en producción
    vector<unsigned char> salt = generarSalt(16);

    // 2) derivar clave con TU PBKDF2 (implementada en pbkdf2.cpp)
    vector<unsigned char> derived = pbkdf2_sha256_bytes(password, salt, iterations, key_len);

    // 3) convertir a Key (alias usado por AES)
    Key aes_key(derived.begin(), derived.end());

    // 4) probar cifrado/descifrado
    string plaintext = "Hola mundo AES con PBKDF2";
    vector<unsigned char> ciphertext = AES256Encriptar(plaintext, aes_key);

    cout << "Salt (hex): " << binAHex(salt) << endl;
    cout << "Derived key (hex): " << binAHex(derived) << endl;
    cout << "Ciphertext (hex): " << binAHex(ciphertext) << endl;

    string recovered = AES256Desencriptar(ciphertext, aes_key);
    cout << "Recovered: " << recovered << endl;

    return 0;
}
