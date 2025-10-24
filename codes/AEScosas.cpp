#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <utility>

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
string to_hex(const vector<unsigned char> &data) {
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


string pbkdf2_sha256(const string &password,const vector<unsigned char> &salt,int iterations, size_t key_len = 32) // 32 bytes = 256 bits
{
    vector<unsigned char> key(key_len);

    int res = PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),salt.data(), (int)salt.size(),iterations, EVP_sha256(),(int)key_len, key.data());

    if (res != 1) {
        cerr << "Error en PBKDF2 derivation\n";
        return "";
    }

    return to_hex(key);
}

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
RoundKeys keySchedule(const Key &masterKey) {
    // TODO: implementar expansión de clave para 14 rondas + inicial
    return RoundKeys{};
}

// Divide el mensaje en bloques de 128 bits y aplica padding si es necesario
vector<Block> divideIntoBlocks(const string &mensaje) {
    // TODO: dividir mensaje y agregar padding PKCS#7 si hace falta
    return vector<Block>{};
}

// Transformaciones de AES sobre un bloque (state 4x4)
Block addRoundKey(const Block &roundKey, const Block &state) {
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
    // TODO: mezclar columnas usando operaciones de Galois Field
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
//Revisar operaciones con bytes 
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

        Block state = addRoundKey(roundKeys[0], block);

        // 13 rondas intermedias
        for (int i = 1; i <= 13; ++i) {

            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(roundKeys[i], state);

        }

        // Ronda final (sin mixColumns)
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(roundKeys[14], state);

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
    return to_hex(vbin);
}

//AES256Encriptar recibe la cadena y la clave de encriptado, retorna la cadena encriptada

//AES256Desencriptar recibe la cadena y la clave de encriptado, retorna la cadena desencriptada



//COSAS A HACEEEERRRRRRR




// Conversión y utilidades
vector<Block> dividirEnBloques(const string &texto);
string blockToString(const Block &bloque);
string quitarPadding(const string &texto);

// Expansión de clave (key schedule)
vector<Key> expandirClaveAES256(const Key &clave);

// Operaciones principales
Block addRoundKey(const Block &state, const Key &subclave);
Block invSubBytes(const Block &state);
Block invShiftRows(const Block &state);
Block invMixColumns(const Block &state);

// Operaciones en el campo GF(2^8)
Byte gmul(Byte a, Byte b); // multiplicación en Galois Field



string AES256Desencriptar(const string &mensajeEncriptado, const Key &clave) {
    // 1. Preparar
    //  - Convertir el texto cifrado en bloques de 16 bytes
    //  - Expandir la clave (key schedule) para obtener todas las subclaves
    //  - Inicializar estructuras de trabajo

    vector<Block> bloques = dividirEnBloques(mensajeEncriptado);
    vector<Key> subclaves = expandirClaveAES256(clave);

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



