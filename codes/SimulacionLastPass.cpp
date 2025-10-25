#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <utility>
#include "AES256Implementacion.cpp"


using namespace std;
//  Tipos de datos 
using Byte = unsigned char;
using Block = vector<Byte>; // 128-bit block = 16 bytes
using Key = vector<Byte>;   // 256-bit key = 32 bytes
using RoundKeys = vector<Block>; // Array de bloques para cada ronda

//pasa de hex a vector de bytes






class Servidor {
public:
    struct Account {
        vector<unsigned char> verifier; // pbkdf2 bytes guardados para verificar 
        vector<unsigned char> salt;     // salt usado para derivación
        vector<pair<string,string>> vault; // pareja<lugar, ciphertext_hex>
        string nombre; 
        string email;
    };

private:
    unordered_map<string, Account> db; // llave: username

public:
    // Crea cuenta: el servidor genera salt y guarda el verificador PBKDF2
    // Devuelve salt al cliente para que derive su clave localmente.
    vector<unsigned char> crearCuenta(const string &username,const string &nombre,const string &email,const string &password,int iterations = 10000,size_t key_len = 32)
    {
        if (db.find(username) != db.end()) {
            return {}; // usuario ya existe devolver vector vacío para indicar error
        }

        // Generar salt 
        vector<unsigned char> salt = generarSalt(16);

        // Derivar verificador en bytes PBKDF2
        vector<unsigned char> verifier = pbkdf2_sha256_bytes(password, salt, iterations, key_len);
        Account acc;
        acc.verifier = verifier;
        acc.salt = salt;
        acc.nombre = nombre;
        acc.email = email;
        db.emplace(username, std::move(acc));

        return salt;
    }

    // Verificar credenciales cliente envía derived = pbkdf2(password, salt_server)
    bool verificarCredenciales(const string &username, const vector<unsigned char> &derived_candidate) {
        auto it = db.find(username);
        if (it == db.end()) return false;
        return constant_time_equal(it->second.verifier, derived_candidate);
    }

    // Retornar vault cifrada (hex strings) para el usuario (si coincide derived)
    vector<pair<string,string>> obtenerVault(const string &username, const vector<unsigned char> &derived_candidate) {
        vector<pair<string,string>> empty;
        if (!verificarCredenciales(username, derived_candidate)) return empty;
        return db[username].vault; // copia (podrías mover/referenciar)
    }

    // Sincronizar vault del usuario (reemplaza en server)
    bool sincronizarVault(const string &username, const vector<unsigned char> &derived_candidate,
                          const vector<pair<string,string>> &vault) {
        if (!verificarCredenciales(username, derived_candidate)) return false;
        db[username].vault = vault;
        return true;
    }

    // Obtener salt almacenado para un usuario (para que el cliente derive su clave)
    // Devuelve empty vector si no existe
    vector<unsigned char> obtenerSalt(const string &username) {
        auto it = db.find(username);
        if (it == db.end()) return {};
        return it->second.salt;
    }
};

//  USUARIO 
class Usuario {
public:
    string nombreUsuario;
    string nombre;
    string email;
private:
    // No almacenamos la contraseña en claro; mantenemos la clave derivada en memoria mientras esté la sesión
    Key claveDerivada; // 32 bytes clave AES
    vector<unsigned char> saltServidor; // salt que usó el servidor al registrar 16 bytes
    vector<pair<string,string>> vault; // <lugar, ciphertext_hex>

public:
    Usuario() = default;

    // Inicializa usuario tras registrar en el servidor: recibe salt generado por servidor
    // password (texto) solo se usa para derivación aquí; no se guarda en claro
    bool inicializarDesdeRegistro(const string &username,const string &nombre_,const string &email_,const string &password,const vector<unsigned char> &salt_from_server,int iterations = 10000,size_t key_len = 32)
    {
        if (salt_from_server.empty()) return false;
        nombreUsuario = username;
        nombre = nombre_;
        email = email_;
        saltServidor = salt_from_server;

        // Derivar clave AES localmente PBKDF2 -> 32 bytes
        vector<unsigned char> derived = pbkdf2_sha256_bytes(password, saltServidor, iterations, key_len);
        claveDerivada.assign(derived.begin(), derived.end());
        // limpiar derived temporal si fuera necesario (depending on pbkdf2_bytes)
        return true;
    }

    // Registrar una contraseña en el vault (cifra con la clave derivada y guarda hex)
    bool registrarContraseña(const string &lugar, const string &contraseña) {
        if (claveDerivada.empty()) return false; // no inicializado / no logueado
        string ciphertext_hex = encryptToHex(contraseña, claveDerivada);
        vault.emplace_back(lugar, ciphertext_hex);
        return true;
    }

    // Solicitar la vault almacenada en server (descargar). Devuelve true si OK.
    bool descargarVaultDesdeServidor(Servidor &srv, int iterations = 10000) {
        if (nombreUsuario.empty() || claveDerivada.empty()) return false;
        // Para verificar, recalculamos derivedCandidate usando la salt del servidor
        vector<unsigned char> salt = srv.obtenerSalt(nombreUsuario);
        if (salt.empty()) return false;
        vector<unsigned char> derivedCandidate = pbkdf2_sha256_bytes(string(), salt, iterations, claveDerivada.size());
        // Pero en la práctica aquí no tenemos la password; en un flujo realidad el cliente derive con su password.
        // En esta simulación supondremos que el cliente ya tiene claveDerivada correcta y la usa para construir derivedCandidate:
        // -> construire derivedCandidate igual a claveDerivada
        derivedCandidate = claveDerivada; // simulación
        auto remoteVault = srv.obtenerVault(nombreUsuario, derivedCandidate);
        if (remoteVault.empty() && !srv.verificarCredenciales(nombreUsuario, derivedCandidate)) return false;
        vault = remoteVault;
        return true;
    }

    // Sincronizar vault local con el servidor (subir)
    bool sincronizarConServidor(Servidor &srv) {
        if (nombreUsuario.empty() || claveDerivada.empty()) return false;
        return srv.sincronizarVault(nombreUsuario, claveDerivada, vault);
    }

    // Obtener vault local (cifrada)
    const vector<pair<string,string>>& obtenerVaultLocal() const { return vault; }

    // (opcional) método para descifrar un entry (requiere claveDerivada)
    // Aquí asumimos que tienes una función AES256DesencriptarBinario(cipher_bin, key) que devuelve plaintext
    string descifrarEntradaHex(const string &ciphertext_hex) {
        if (claveDerivada.empty()) return {};
        vector<unsigned char> bin = hexABytes(ciphertext_hex);
        string cipher_bin((char*)bin.data(), bin.size());
        string plain = AES256Desencriptar(cipher_bin, claveDerivada); 
        return plain;
    }
};




int main(){
    //Se quiere simular lastpass 
    string password = "MiClaveSecreta";
    cout << "Clave original: " << password << endl;

    // --- Generar salt y clave derivada ---
    vector<unsigned char> salt = generarSalt();
    string clave_hex = pbkdf2_sha256_hex(password, salt, 10000);
    cout << "Clave derivada (PBKDF2-SHA256): " << clave_hex << endl;



}
