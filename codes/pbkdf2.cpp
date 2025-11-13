#include "pbkdf2.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <vector>
#include <string>
#include <stdexcept>
#include <sstream>
#include <iomanip>

using namespace std;


vector<unsigned char> generarSalt(size_t len) {
    vector<unsigned char> salt(len);
    if (RAND_bytes(salt.data(), (int)len) != 1) {
        throw runtime_error("RAND_bytes failed");
    }
    return salt;
}

string binAHex(const vector<unsigned char> &data) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char b : data) ss << setw(2) << (int)b;
    return ss.str();
}


// Implementación manual PBKDF2-HMAC-SHA256 (RFC 2898 style)
vector<unsigned char> pbkdf2_sha256_bytes(
    const string &password,
    const vector<unsigned char> &salt,
    int iterations,
    size_t key_len)
{
    if (iterations <= 0) throw runtime_error("pbkdf2: iterations must be > 0");

    const size_t hLen = 32; // SHA-256 output size
    size_t l = (key_len + hLen - 1) / hLen; // bloques necesarios (ceil)
    size_t r = key_len - (l - 1) * hLen;    // bytes en último bloque

    vector<unsigned char> dk(key_len, 0); // Vector donde se guarda la clave croptografica derivada
                                        // Tiene la misma longitud que la contraseña huaman en bytes
    vector<unsigned char> U(hLen);  
    vector<unsigned char> T(hLen); 

    const unsigned char *pwd = reinterpret_cast<const unsigned char*>(password.data());
    int pwd_len = static_cast<int>(password.size());

    // buffer salt || INT(i)
    vector<unsigned char> salt_int(salt);
    salt_int.resize(salt.size() + 4); // Se le agregan 4 bytes más para determinar el INT(i) es decir 32 bits.. Entero de 34 bits

    for (uint32_t block = 1; block <= (uint32_t)l; ++block) {
        // INT(block) big-endian
        salt_int[salt.size() + 0] = static_cast<unsigned char>((block >> 24) & 0xFF); //filtra los 8 bits menos relevantes de block
        salt_int[salt.size() + 1] = static_cast<unsigned char>((block >> 16) & 0xFF);  
        salt_int[salt.size() + 2] = static_cast<unsigned char>((block >> 8) & 0xFF);
        salt_int[salt.size() + 3] = static_cast<unsigned char>((block) & 0xFF);

        unsigned int out_len = 0;  // guarda el tamaño del bloque de la clave pasada por al función HASH hmac-sha256
        // U1 = HMAC(P, S || INT(i))
        if (!HMAC(EVP_sha256(), pwd, pwd_len, salt_int.data(), (int)salt_int.size(), U.data(), &out_len))
            throw runtime_error("HMAC failed (U1)");
        if (out_len != hLen) throw runtime_error("HMAC unexpected length");  // si el tamaño del bloque en bytes no es igual al definido por el User

        // T = U1
        for (size_t i = 0; i < hLen; ++i) T[i] = U[i]; // Primera iteración, simplemente se copia en T1

        // Uj for j = 2..iterations
        for (int j = 1; j < iterations; ++j) {
            if (!HMAC(EVP_sha256(), pwd, pwd_len, U.data(), (int)hLen, U.data(), &out_len))
                throw runtime_error("HMAC failed (Uj)");
            if (out_len != hLen) throw runtime_error("HMAC unexpected length");  // Verifica longitud de clave generada, igual que en linea 69
            for (size_t k = 0; k < hLen; ++k) T[k] ^= U[k];  // Guarda el XOR operation de los bloques Ui
        }

        // copiar T al dk
        size_t offset = (block - 1) * hLen; // Determina bloque actual donde se debe concatenar Ti
        size_t to_copy = (block == l) ? r : hLen;  // Determinar la longitud del bloque
        for (size_t c = 0; c < to_copy; ++c) dk[offset + c] = T[c]; // Concatenación de los bloques Ti
                                                                    // Copia cada uno de los bytes del bloque Ti
    }

    return dk;
}