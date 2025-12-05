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

// ===================== SERVIDOR ============================
class Servidor {
public:
    struct Account {
        vector<unsigned char> auth_hash; 
        vector<unsigned char> salt;
        vector<pair<string, vector<unsigned char>>> vault;
        string nombre;
        string email;
    };

private:
    unordered_map<string, Account> db;

public:
    vector<unsigned char> generarSaltParaRegistro() {
        return generarSalt(16);
    }

    bool registrarUsuario(const string &u,const string &n,const string &e,
                          const vector<unsigned char> &ah,const vector<unsigned char> &s){
        if (db.count(u)) return false;
        Account acc{ah,s,{},n,e};
        db.emplace(u, move(acc));
        return true;
    }

    bool verificarCredenciales(const string &username, const vector<unsigned char> &candidate_hash){
        return db.count(username) && constant_time_equal(db[username].auth_hash, candidate_hash);
    }

    vector<unsigned char> obtenerSalt(const string &username) {
        if (!db.count(username)) return {};
        return db[username].salt;
    }

    vector<pair<string, vector<unsigned char>>> obtenerVault(const string &username,
                                                             const vector<unsigned char> &auth_hash){
        if (!verificarCredenciales(username, auth_hash)) return {};
        return db[username].vault;
    }

    bool sincronizarVault(const string &username,
                          const vector<unsigned char> &auth_hash,
                          const vector<pair<string, vector<unsigned char>>> &vault){
        if (!verificarCredenciales(username, auth_hash)) return false;
        db[username].vault = vault;
        return true;
    }
};

// ===================== CLIENTE ============================
class Usuario {
public:
    string username, nombre, email;

private:
    vector<unsigned char> masterKey;
    vector<unsigned char> authHash;
    vector<unsigned char> salt;
    vector<pair<string, vector<unsigned char>>> vault;
    int N = 10000;

public:
    bool registrarEnServidor(Servidor &server, const string &user,const string &nom,
                             const string &emai,const string &password){
        username = user; nombre = nom; email = emai;
        salt = server.generarSaltParaRegistro();
        masterKey = pbkdf2_sha256_bytes(password, salt, N, 32);
        authHash = pbkdf2_sha256_bytes(password, salt, N+1, 32);
        return server.registrarUsuario(username, nombre, email, authHash, salt);
    }

    bool iniciarSesion(Servidor &server, const string &password){
        salt = server.obtenerSalt(username);
        masterKey = pbkdf2_sha256_bytes(password, salt, N, 32);
        authHash = pbkdf2_sha256_bytes(password, salt, N+1, 32);
        return server.verificarCredenciales(username, authHash);
    }

    bool guardarPassword(const string &lugar, const string &pass){
        if (masterKey.empty()) return false;
        vault.emplace_back(lugar, AES256Encriptar(pass, masterKey));
        return true;
    }

    bool subirVault(Servidor &server){
        return server.sincronizarVault(username, authHash, vault);
    }

    bool bajarVault(Servidor &server){
        auto temp = server.obtenerVault(username, authHash);
        if (temp.empty()) return false;
        vault = temp;
        return true;
    }

    void mostrarVault(){
        cout << "\n--- Vault ("<<username<<") ---\n";
        for (auto &i : vault){
            cout << i.first <<" : "<< AES256Desencriptar(i.second, masterKey) << endl;
        }
    }

    void mostrarVaultEncriptada(){
        cout << "\n--- Vault Encriptada ("<<username<<") ---\n";
        for (auto &i : vault){
            cout << i.first << " : ";
            for (unsigned char c : i.second)
                cout << std::hex << setw(2) << setfill('0') << (int)c;
            cout << endl;
        }
    }
};

// ===================== MAIN ============================
int main(){
    Servidor server;
    Usuario cliente;

    cliente.registrarEnServidor(server, "CarlosUser", "Carlos", "r@correo.com", "SuperClaveSuperSegura123456789");
    cliente.iniciarSesion(server, "SuperClave123");

    cliente.guardarPassword("Instagram", "Inst4gram!2024");
    cliente.guardarPassword("Twitter", "Xtwitt3r#Pass");
    cliente.guardarPassword("TikTok", "T1kTok_P455w0rd");

    cliente.guardarPassword("Google Drive", "Goog13-Dr!ve-2024");
    cliente.guardarPassword("PayPal", "P4yP4l$ecure!");
    cliente.guardarPassword("BBVA", "BBV4-S3gur0-98");

    cliente.guardarPassword("Amazon", "Amaz0n2024_Pass");
    cliente.guardarPassword("MercadoLibre", "M3rcad0L!brePass");
    cliente.guardarPassword("Netflix", "N3tfl1x-H0g4r");
    cliente.guardarPassword("Spotify", "Sp0t1fy_Premium!");
    cliente.guardarPassword("Steam", "St3@mGamer2024");


    cliente.subirVault(server);

    cliente.bajarVault(server);
    cliente.mostrarVault();
    cliente.mostrarVaultEncriptada();
}
