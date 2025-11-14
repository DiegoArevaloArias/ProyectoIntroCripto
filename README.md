#  Estudio e Implementación del Manejo de Claves en la Industria  


###  Integrantes del Equipo
- **Oscar Fabián Sierra Daza**
- **Diego Alejandro Arévalo Arias**
- **Miguel Angel Saenz Valcarcel**
- **Diego Felipe Cabrera Salamanca**

---

##  Descripción del Proyecto

El objetivo de este proyecto es estudiar e implementar las diferentes formas en las cuales se manejan contraseñas y claves en entornos industriales.  
Se analizarán tanto mecanismos de almacenamiento (hashing con *salt* y *pepper*, gestores de contraseñas, bases de datos de credenciales) como mecanismos de gestión y uso.

Se cubrirán ejemplos reales como:
- Proveedores de correo y servicios web (Google, Microsoft, etc.)
- Aplicaciones bancarias y comercio electrónico
- Gestores de contraseñas (LastPass)


---

##  Implementación

Se desarrollarán simulaciones y prototipos que reproduzcan las técnicas más comunes en el manejo de contraseñas y claves:

- **Almacenamiento seguro:**  
  Hashing de contraseñas (PBKDF2, bcrypt, scrypt, Argon2), con *salt* y *pepper*.  
  Gestión de parámetros: coste, iteraciones, memoria y evaluación del coste computacional.

- **Gestión de secretos:**  
  Simulación con sistemas tipo Vault/KMS: almacenamiento, rotación automática y políticas de acceso.

- **Autenticación:**  
  Flujos básicos de SSO/OAuth y MFA (TOTP), analizando impacto en seguridad y usabilidad.

>  *Posibilidad de ampliación según tiempos del proyecto*

---

##  Evaluación y Análisis de Ataques

Se estudiarán diferentes técnicas de ataque y su impacto:

- **Fuerza bruta y diccionario:**  
  Tiempos de recuperación bajo distintos algoritmos y parámetros de hashing.

- **Rainbows tables y precomputación:**  
  Efectividad de sal y pepper como mitigación.

- **Ataques a gestión de secretos:**  
  Explotación de configuraciones erróneas (permisos laxos, falta de rotación).

 Se registrarán métricas como tiempo medio, intentos por segundo y tasa de éxito.

---

##  Resultados Esperados / Entregables

- Implementaciones de los esquemas de manejo de contraseñas.
- Informe experimental con métricas:
  - Tiempos de cracking por algoritmo
  - Comparativa coste/seguridad
  - Buenas y malas configuraciones
- Recomendaciones prácticas para la industria:
  - Políticas de contraseñas
  - Rotación de claves
  - Parámetros mínimos recomendados

---

##  Objetivos

- Identificar requisitos para contraseñas y gestión de claves seguras.
- Estudiar y comparar métodos industriales de almacenamiento y gestión.
- Implementar y documentar prototipos para analizar complejidad y seguridad.
- Diseñar ataques para estimar tiempos de cracking con diferentes parámetros.
- Proponer recomendaciones prácticas para la creación y gestión de contraseñas.

---


##  Archivos

- Codes:
Iplementaciones en c++
  - AES256Implementacion.cpp
  - SimulacionLastPass.cpp
  - argon2_simplified.cpp
  - blake2b.cpp
  - pbkdf2.cpp
  - main.cpp
Headers
  - AES256Implementacion.h
  - argon2_simplified.h
  - blake2b.h
  - pbkdf2.h

Cuadernos en python
  - scrypt.ipynb
  - bcrypt.ipynb


## Como compilar y ejecutar
Compilar: 
```
g++ -std=c++17 -O2 main.cpp pbkdf2.cpp AES256Implementacion.cpp -o output/main.exe -lssl -lcrypto
```
Ejecutar:
```
output/main.exe
```

  


---
