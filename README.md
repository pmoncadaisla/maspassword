# MasPassword

Gestor de contrasenas zero-knowledge con cifrado extremo a extremo. Las contrasenas se cifran en el cliente antes de enviarse al servidor, lo que garantiza que ni siquiera los administradores del sistema pueden acceder a los datos en texto plano.

## Caracteristicas

- **Zero-Knowledge:** el servidor nunca tiene acceso a las credenciales en texto plano.
- **Autenticacion SRP-6a:** protocolo Secure Remote Password que evita transmitir la contrasena por la red.
- **Equipos y boveda compartida:** comparte bovedas con otros usuarios mediante claves RSA cifradas por usuario.
- **PWA:** aplicacion web instalable con soporte offline via Service Worker.
- **Extension de navegador:** autocompletado de credenciales (Manifest V3, compatible con Chrome/Edge).
- **Versionado de items:** control de versiones para evitar conflictos en actualizaciones concurrentes.
- **Anti-enumeracion:** respuestas ficticias ante emails invalidos para prevenir la enumeracion de usuarios.

## Arquitectura

```
maspassword/
├── cmd/
│   ├── server/          # Punto de entrada del servidor HTTP
│   └── client/          # Cliente CLI para pruebas
├── internal/
│   ├── config/          # Configuracion desde variables de entorno
│   ├── database/        # Conexion a PostgreSQL y migraciones
│   ├── models/          # Modelos de dominio
│   ├── repository/      # Capa de acceso a datos
│   ├── service/         # Logica de negocio
│   ├── handler/         # Handlers HTTP
│   ├── middleware/       # JWT, CORS, logging, errores
│   ├── router/          # Definicion de rutas
│   └── srp/             # Gestion de sesiones SRP
├── pkg/dto/             # Data Transfer Objects
├── web/                 # Frontend PWA (vanilla JS)
├── extension/           # Extension de navegador (Manifest V3)
└── scripts/             # Scripts de utilidad
```

### Stack tecnologico

| Capa | Tecnologia |
|------|-----------|
| Backend | Go 1.26, Gin |
| Base de datos | PostgreSQL, sqlx, golang-migrate |
| Autenticacion | SRP-6a, JWT |
| Frontend | HTML5, CSS3, JavaScript vanilla |
| Extension | Manifest V3 (Chrome/Edge) |

## API

### Endpoints publicos

| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| POST | `/auth/signup` | Registro con verifier SRP |
| POST | `/auth/login/step1` | Handshake SRP paso 1 |
| POST | `/auth/login/step2` | Handshake SRP paso 2, devuelve JWT |

### Endpoints protegidos (JWT)

| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| GET | `/api/vaults` | Listar bovedas accesibles |
| POST | `/api/vaults` | Crear boveda personal |
| GET | `/api/vaults/:id/items` | Listar items de una boveda |
| POST | `/api/vaults/:id/items` | Crear item cifrado |
| PUT | `/api/vaults/:id/items/:itemId` | Actualizar item |
| POST | `/api/vaults/:id/share` | Compartir boveda con equipo |
| POST | `/api/teams` | Crear equipo |
| GET | `/api/teams` | Listar equipos del usuario |
| POST | `/api/teams/:teamId/members` | Anadir miembro |
| POST | `/api/users/keys` | Subir par de claves RSA |

---

## Desarrollo

### Requisitos previos

- Go >= 1.26
- PostgreSQL >= 14

### Configuracion de la base de datos

```bash
bash scripts/setup-db.sh
```

Esto crea el usuario `vault_user`, la base de datos `vault_internal` y la extension `uuid-ossp`.

### Variables de entorno

Copia `.env.example` y ajusta los valores:

```bash
cp .env.example .env
```

| Variable | Descripcion | Valor por defecto |
|----------|-------------|-------------------|
| `DATABASE_URL` | Cadena de conexion PostgreSQL | `postgres://vault_user:vault_pass@localhost:5432/vault_internal?sslmode=disable` |
| `JWT_SECRET` | Secreto para firmar tokens JWT | — (obligatorio) |
| `SERVER_PORT` | Puerto del servidor HTTP | `8080` |
| `CORS_ORIGINS` | Origenes permitidos para CORS | `http://localhost:3000` |
| `SRP_BITS` | Tamano de clave SRP | `2048` |

### Compilar y ejecutar

```bash
# Compilar el servidor
go build -o maspassword ./cmd/server

# Ejecutar (aplica migraciones automaticamente)
./maspassword
```

El servidor arranca en `http://localhost:8080` y sirve la PWA en la raiz.

### Cliente CLI

Disponible para pruebas rapidas:

```bash
go build -o client ./cmd/client

./client signup user@example.com password
./client login user@example.com password
./client vaults <token> list
./client vaults <token> create "Mi boveda"
./client items <token> <vault_id> list
```

### Tests

```bash
go test ./...
```

### Extension de navegador

1. Abre `chrome://extensions` en Chrome/Edge.
2. Activa el **modo desarrollador**.
3. Haz clic en **Cargar extension sin empaquetar** y selecciona la carpeta `extension/`.
