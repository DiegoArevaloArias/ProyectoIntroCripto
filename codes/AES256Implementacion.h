#ifndef AES256IMPLEMENTACION_H
#define AES256IMPLEMENTACION_H

#include <string>
#include <vector>

// reusa tus aliases para claridad
using Byte = unsigned char;
using Block = std::vector<Byte>;
using Key = std::vector<Byte>;

// Prototipos relevantes que exporta tu implementación AES
std::vector<unsigned char> AES256Encriptar(const std::string &mensaje, const Key &clave);
std::string AES256Desencriptar(const std::vector<unsigned char> &mensajeEncriptado, const Key &clave);



#endif // AES256IMPLEMENTACION_H
