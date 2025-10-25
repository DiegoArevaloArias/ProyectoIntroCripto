#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

///Incluir el pbkdf2 de Diego


using namespace std;
//  Tipos de datos 
using Byte = unsigned char;
using Block = vector<Byte>; // 128-bit block = 16 bytes
using Key = vector<Byte>;   // 256-bit key = 32 bytes
using RoundKeys = vector<Block>; // Array de bloques para cada ronda

//pasa de hex a vector de bytes
vector<Byte> hexABytes(const string &hex) {
    vector<Byte> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        Byte byte = (Byte)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

//  Convierte bytes a string hex 
string binAHex(const vector<unsigned char> &data) {
    stringstream ss;
    ss<<hex<<setfill('0');
    for (unsigned char c : data){
        ss << setw(2) << (int)c;
    }
    return ss.str();
}

//  Genera salt aleatorio 
vector<unsigned char> generarSalt(size_t len = 16) {
    vector<unsigned char> salt(len);
    RAND_bytes(salt.data(), (int)len);
    return salt;
}

// Función PBKDF2-SHA256 
// Recibe password, salt y número de iteraciones
// Devuelve la clave derivada en hex (para AES o verificación)
// Actualmente se usa la implementacion de la libreria de openssl


Key pbkdf2_sha256_bytes(const string &password,const vector<unsigned char> &salt,int iterations, size_t key_len = 32) // 32 bytes = 256 bits
{
    vector<unsigned char> key(key_len);

    int res = PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),salt.data(), (int)salt.size(),iterations, EVP_sha256(),(int)key_len, key.data());

    if (res != 1) {
        cerr << "Error en PBKDF2 derivation\n";
        throw runtime_error("PBKDF2 failed");
    }

    return key;
}

string pbkdf2_sha256_hex(const string &password,const vector<unsigned char> &salt,int iterations, size_t key_len = 32){
    return binAHex(pbkdf2_sha256_bytes(password,salt,iterations));
}


//sbox usada para trnsformaciones de bytes
const Byte sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};



//  Funciones principales de AES-256 

// Expandir clave maestra en claves de ronda
// Expansión de clave para AES-256 (Nk=8, Nr=14)

RoundKeys keySchedule(const Key &masterKey) {
    const int Nk = 8;   // 32 bytes / 4 = 8 palabras
    const int Nb = 4;   // columnas
    const int Nr = 14;  // rondas AES-256
    const int words = Nb * (Nr + 1); // 4*(14+1)=60 palabras

    if (masterKey.size() != 32) {
        throw std::runtime_error("keySchedule: masterKey must be 32 bytes for AES-256");
    }

    // Helpers locales
    auto packWord = [](const Byte b0, const Byte b1, const Byte b2, const Byte b3) -> uint32_t {
        return ( (uint32_t)b0 << 24 ) | ( (uint32_t)b1 << 16 ) | ( (uint32_t)b2 << 8 ) | (uint32_t)b3;
    };
    auto unpackWord = [](uint32_t w, Byte &b0, Byte &b1, Byte &b2, Byte &b3) {
        b0 = (Byte)((w >> 24) & 0xFF);
        b1 = (Byte)((w >> 16) & 0xFF);
        b2 = (Byte)((w >> 8) & 0xFF);
        b3 = (Byte)(w & 0xFF);
    };
    auto RotWord = [](uint32_t w) -> uint32_t {
        return ((w << 8) | (w >> 24)) & 0xFFFFFFFFu;
    };
    auto SubWord = [&](uint32_t w) -> uint32_t {
        Byte a = (Byte)((w >> 24) & 0xFF);
        Byte b = (Byte)((w >> 16) & 0xFF);
        Byte c = (Byte)((w >> 8) & 0xFF);
        Byte d = (Byte)(w & 0xFF);
        return packWord(sbox[a], sbox[b], sbox[c], sbox[d]);
    };

    // Rcon (suficiente para AES-256)
    const Byte rconBytes[] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };

    // w = array de palabras (uint32_t)
    std::vector<uint32_t> w(words, 0);

    // Inicializar primeras Nk palabras con la clave maestra
    for (int i = 0; i < Nk; ++i) {
        int base = 4 * i;
        w[i] = packWord(masterKey[base], masterKey[base + 1], masterKey[base + 2], masterKey[base + 3]);
    }

    // Expandir
    for (int i = Nk; i < words; ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ ( (uint32_t)rconBytes[i / Nk] << 24 );
        } else if (i % Nk == 4) { // regla para AES-256 (subword extra)
            temp = SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }

    // Construir RoundKeys: cada ronda tiene 4 palabras = 16 bytes
    RoundKeys roundKeys;
    roundKeys.reserve(Nr + 1);
    for (int round = 0; round <= Nr; ++round) {
        Block rk(16);
        for (int j = 0; j < 4; ++j) {
            uint32_t word = w[round * 4 + j];
            Byte b0, b1, b2, b3;
            unpackWord(word, b0, b1, b2, b3);
            // Mantener el orden de bytes tal cual (b0..b3)
            rk[4 * j + 0] = b0;
            rk[4 * j + 1] = b1;
            rk[4 * j + 2] = b2;
            rk[4 * j + 3] = b3;
        }
        roundKeys.push_back(rk);
    }

    return roundKeys;
}



// Divide el mensaje en bloques de 16 bytes y aplica padding PKCS#7
vector<Block> divideIntoBlocks(const string &mensaje) {
    const size_t blockSize = 16;
    vector<Block> blocks;

    size_t n = mensaje.size();
    size_t fullBlocks = n / blockSize;
    size_t rem = n % blockSize;

    // copiar bloques completos
    for (size_t k = 0; k < fullBlocks; ++k) {
        Block b(blockSize);
        size_t base = k * blockSize;
        for (size_t i = 0; i < blockSize; ++i) b[i] = static_cast<Byte>(mensaje[base + i]);
        blocks.push_back(std::move(b));
    }

    // manejar último bloque y padding PKCS#7
    if (rem == 0) {
        // si el mensaje ya está alineado, añadir un bloque completo de padding (valor = 16)
        Block padBlock(blockSize, static_cast<Byte>(blockSize));
        blocks.push_back(std::move(padBlock));
    } else {
        // crear bloque incompleto y rellenar con valor pad = (16 - rem)
        Block last(blockSize, 0);
        size_t base = fullBlocks * blockSize;
        for (size_t i = 0; i < rem; ++i) last[i] = static_cast<Byte>(mensaje[base + i]);
        Byte pad = static_cast<Byte>(blockSize - rem);
        for (size_t i = rem; i < blockSize; ++i) last[i] = pad;
        blocks.push_back(std::move(last));
    }

    return blocks;
}

// Transformaciones de AES sobre un bloque (state 4x4)
Block addRoundKey(const Block &state, const Block &roundKey) {
    Block nuevoState(16);
    // XOR del state con la clave de ronda
    for (int i = 0; i < 16; i++)
    {
        nuevoState[i]=state[i]^roundKey[i];
    }
    
    return nuevoState;
}

Block subBytes(const Block &state) {
    Block nuevoState(state.size());
    for(int i=0; i<state.size(); i++){
        nuevoState[i]=sbox[state[i]];
    }
    return nuevoState;
}

Block shiftRows(const Block &state) {
    Block nuevoState(16);
    //Fila 1
    nuevoState[0]=state[0];
    nuevoState[1]=state[1];
    nuevoState[2]=state[2];
    nuevoState[3]=state[3];

    //Fila 2
    nuevoState[4]=state[5];
    nuevoState[5]=state[6];
    nuevoState[6]=state[7];
    nuevoState[7]=state[4];

    //Fila 3
    nuevoState[8]=state[10];
    nuevoState[9]=state[11];
    nuevoState[10]=state[8];
    nuevoState[11]=state[9];


    //Fila 4
    nuevoState[12]=state[15];
    nuevoState[13]=state[12];
    nuevoState[14]=state[13];
    nuevoState[15]=state[14];

    return nuevoState;
}



inline Byte gmul2(Byte b) {
    return (b < 0x80) ? (b << 1) : ((b << 1) ^ 0x1b);
}
inline Byte gmul3(Byte b) {
    return gmul2(b) ^ b;
}

Block mixColumns(const Block &state) {
    Block nuevoState(16);
    for (int i = 0; i < 4; i++)
    {
        Byte s0=state[i];
        Byte s1=state[i+4];
        Byte s2=state[i+8];
        Byte s3=state[i+12];


        nuevoState[i]=gmul2(s0)^gmul3(s1)^s2^s3; //s0' transformacion
        nuevoState[i+4]=s0^gmul2(s1)^gmul3(s2)^s3; //s1' transformacion
        nuevoState[i+8]=s0^s1^gmul2(s2)^gmul3(s3);   //s2' transformacion
        nuevoState[i+12]=gmul3(s0)^s1^s2^gmul2(s3);   //s3' transformacion
        /*  
s0' = (2 • s0) ⊕ (3 • s1) ⊕ s2 ⊕ s3
s1' = s0 ⊕ (2 • s1) ⊕ (3 • s2) ⊕ s3
s2' = s0 ⊕ s1 ⊕ (2 • s2) ⊕ (3 • s3)
s3' = (3 • s0) ⊕ s1 ⊕ s2 ⊕ (2 • s3)
        */


    }
    

    return nuevoState;
}

// Convierte una matriz 4x4 (state) en bytes lineales
Block convertMatrixToBytes(const Block &state) {
    return state;
}




// --- Función AES-256 completa ---
string AES256Encriptar(const string &mensaje, const Key &clave) {
    // 1. Expandir clave
    RoundKeys roundKeys = keySchedule(clave);

    // 2. Dividir mensaje en bloques
    vector<Block> bloques = divideIntoBlocks(mensaje);

    // 3. Inicializar resultado
    string cipherText;

    // 4. Encriptar cada bloque
    for (Block &block : bloques) {

        Block state = addRoundKey(block,roundKeys[0]);

        // 13 rondas intermedias
        for (int i = 1; i <= 13; ++i) {

            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, roundKeys[i]);

        }

        // Ronda final (sin mixColumns)
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state,roundKeys[14]);

        // Convertir state a bytes y concatenar
        Block cipherBlock = convertMatrixToBytes(state);
        cipherText.append(cipherBlock.begin(), cipherBlock.end());
    }

    return cipherText;
}

bool constant_time_equal(const vector<unsigned char>& a, const vector<unsigned char>& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

string encryptToHex(const string &plaintext, const Key &key) {
    string bin = AES256Encriptar(plaintext, key); // tu función existente que devuelve bytes binarios en string
    vector<unsigned char> vbin(bin.begin(), bin.end());
    return binAHex(vbin);
}

//AES256Encriptar recibe la cadena y la clave de encriptado, retorna la cadena encriptada










//AES256Desencriptar recibe la cadena y la clave de encriptado, retorna la cadena desencriptada



const Byte invSbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

// Conversión y utilidades
// Convierte el texto cifrado en bloques de 16 bytes
vector<Block> splitCiphertextBlocks(const string &ciphertext) {
    vector<Block> bloques;
    if (ciphertext.size() % 16 != 0) {
        throw runtime_error("Ciphertext length not multiple of 16 bytes");
    }
    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        Block b(16);
        for (int j = 0; j < 16; ++j) b[j] = static_cast<Byte>(ciphertext[i + j]);
        bloques.push_back(std::move(b));
    }
    return bloques;
}


// Convierte un bloque de 16 bytes a std::string
string blockToString(const Block &bloque) {
    string s;
    s.reserve(16);
    for (Byte b : bloque)
        s.push_back(static_cast<char>(b));
    return s;
}


// Elimina padding PKCS#7 del texto
string quitarPadding(const string &texto) {
    if (texto.empty()) return texto;

    unsigned char pad = texto.back();

    // Validar padding
    if (pad == 0 || pad > 16) {
        cerr << "[WARN] Padding inválido detectado.\n";
        return texto;
    }
    if (texto.size() < pad) {
        cerr << "[WARN] Padding mayor que el tamaño del texto.\n";
        return texto;
    }

    for (size_t i = texto.size() - pad; i < texto.size(); i++) {
        if ((unsigned char)texto[i] != pad) {
            cerr << "[WARN] Padding inconsistente.\n";
            return texto;
        }
    }

    return texto.substr(0, texto.size() - pad);
}

// Operaciones principales
Block invSubBytes(const Block &state){

    Block nuevoState(state.size());
    for(int i=0; i<state.size(); i++){
        nuevoState[i]=invSbox[state[i]];
    }
    return nuevoState;
}


Block invShiftRows(const Block &state){

    Block nuevoState(16);
    //Fila 1
    nuevoState[0]=state[0];
    nuevoState[1]=state[1];
    nuevoState[2]=state[2];
    nuevoState[3]=state[3];

    //Fila 2
    nuevoState[4]=state[7];
    nuevoState[5]=state[4];
    nuevoState[6]=state[5];
    nuevoState[7]=state[6];

    //Fila 3
    nuevoState[8]=state[10];
    nuevoState[9]=state[11];
    nuevoState[10]=state[8];
    nuevoState[11]=state[9];


    //Fila 4
    nuevoState[12]=state[13];
    nuevoState[13]=state[14];
    nuevoState[14]=state[15];
    nuevoState[15]=state[12];

    return nuevoState;

}


inline Byte gmul4(Byte b) {
    return gmul2(gmul2(b));
}
inline Byte gmul8(Byte b) { 
    return gmul2(gmul4(b));
}

// 9 = 8 + 1
inline Byte gmul9(Byte b)  {
    return gmul8(b) ^ b;
}
// 11 (0x0b) = 8 + 2 + 1
inline Byte gmul11(Byte b) {
    return gmul8(b) ^ gmul2(b) ^ b; 
}
// 13 (0x0d) = 8 + 4 + 1
inline Byte gmul13(Byte b) { 
    return gmul8(b) ^ gmul4(b) ^ b; 
}
// 14 (0x0e) = 8 + 4 + 2
inline Byte gmul14(Byte b) { 
    return gmul8(b) ^ gmul4(b) ^ gmul2(b); 
}

Block invMixColumns(const Block &state) {
    Block nuevoState(16);
    for (int i = 0; i < 4; ++i) {
        Byte s0 = state[i];
        Byte s1 = state[i + 4];
        Byte s2 = state[i + 8];
        Byte s3 = state[i + 12];

        // Aplicando la matriz 0e 0b 0d 09 (columna a columna)
        nuevoState[i]  = gmul14(s0)^gmul11(s1)^gmul13(s2)^gmul9(s3);
        nuevoState[i+4]= gmul9(s0)^gmul14(s1)^gmul11(s2)^gmul13(s3);
        nuevoState[i+8]= gmul13(s0)^gmul9(s1)^gmul14(s2)^gmul11(s3);
        nuevoState[i+12]= gmul11(s0)^gmul13(s1)^gmul9(s2)^gmul14(s3);
    }
    return nuevoState;
}

string AES256Desencriptar(const string &mensajeEncriptado, const Key &clave) {
    // 1. Preparar
    //  - Convertir el texto cifrado en bloques de 16 bytes
    //  - Expandir la clave (key schedule) para obtener todas las subclaves
    //  - Inicializar estructuras de trabajo

    vector<Block> bloques = splitCiphertextBlocks(mensajeEncriptado);
    RoundKeys subclaves = keySchedule(clave);

    string resultado;

    // 2. Procesar cada bloque
    for (Block &bloque : bloques) {

        //  Etapas inversas del AES 
        // recordando que AES-256 tiene 14 rondas

        // 2.1 AddRoundKey última subclave
        bloque = addRoundKey(bloque, subclaves[14]);

        // 2.2 Rondas inversas (de 13 a 1)
        for (int ronda = 13; ronda > 0; ronda--) {
            bloque = invShiftRows(bloque);
            bloque = invSubBytes(bloque);
            bloque = addRoundKey(bloque, subclaves[ronda]);
            bloque = invMixColumns(bloque);
        }

        // 2.3 Ronda final (sin invMixColumns)
        bloque = invShiftRows(bloque);
        bloque = invSubBytes(bloque);
        bloque = addRoundKey(bloque, subclaves[0]);

        // 2.4 Añadir bloque desencriptado al resultado
        resultado += blockToString(bloque);
    }

    // 3. Quitar padding (PKCS#7 u otro)
    resultado = quitarPadding(resultado);

    return resultado;
}



//Funciones para Simulacion LASTPass
bool constant_time_equal(const vector<unsigned char>& a, const vector<unsigned char>& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

string encryptToHex(const string &plaintext, const Key &key) {
    string bin = AES256Encriptar(plaintext, key); // tu función existente que devuelve bytes binarios en string
    vector<unsigned char> vbin(bin.begin(), bin.end());
    return binAHex(vbin);
}



