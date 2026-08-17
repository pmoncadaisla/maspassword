# Sésamo

[![Release](https://github.com/pmoncadaisla/maspassword/actions/workflows/release.yml/badge.svg)](https://github.com/pmoncadaisla/maspassword/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/pmoncadaisla/maspassword)](https://github.com/pmoncadaisla/maspassword/releases/latest)

Sésamo (antes MasPassword) es un gestor de contrasenas zero-knowledge con cifrado extremo a extremo. Las contrasenas se cifran en el cliente antes de enviarse al servidor, lo que garantiza que ni siquiera los administradores del sistema pueden acceder a los datos en texto plano.

## Instalacion rapida (Docker)

```bash
git clone https://github.com/pmoncadaisla/maspassword.git && cd maspassword
JWT_SECRET=$(openssl rand -hex 32) docker compose up -d
# abre http://localhost:8080
```

Levanta PostgreSQL y el servidor (imagen multi-arch amd64/arm64) con las migraciones aplicadas. App de escritorio para macOS y extension de Chrome: en [Releases](https://github.com/pmoncadaisla/maspassword/releases/latest). Detalles en [Instalacion](#instalacion).

## Caracteristicas

- **Zero-Knowledge:** el servidor nunca tiene acceso a las credenciales en texto plano.
- **Autenticacion SRP-6a:** protocolo Secure Remote Password que evita transmitir la contrasena por la red.
- **Equipos y boveda compartida:** comparte bovedas con otros usuarios mediante claves RSA cifradas por usuario.
- **PWA:** aplicacion web instalable con soporte offline via Service Worker.
- **Extension de navegador:** autocompletado de credenciales (Manifest V3, compatible con Chrome/Edge).
- **Versionado de items:** control de versiones para evitar conflictos en actualizaciones concurrentes.
- **Exportacion interoperable:** descarga la boveda como `.kdbx` (KeePass 4, cifrado con su propia contrasena), CSV o JSON. El descifrado y el cifrado del fichero ocurren en el navegador; el servidor solo ve texto cifrado.
- **Mover y copiar items entre bovedas:** el item se vuelve a cifrar con la clave de destino, util cuando algo personal pasa a ser del equipo.
- **Borrado de bovedas:** el propietario (o un admin del equipo) puede eliminar una boveda con confirmacion escribiendo su nombre; items, historial, claves y comparticiones caen en cascada.
- **Anti-enumeracion:** respuestas ficticias ante emails invalidos para prevenir la enumeracion de usuarios.

## Instalacion

Los binarios se publican en [Releases](https://github.com/pmoncadaisla/maspassword/releases) y la imagen Docker en GHCR. GitHub Actions los genera al pushear un tag `v*` (ver `.github/workflows/release.yml`). Como el cifrado es de extremo a extremo, publicar binarios e imagenes no expone nada: el servidor solo maneja datos cifrados.

### App de escritorio (macOS)

1. Descarga `Sesamo-<version>-macos-universal.dmg` desde Releases. Es un binario universal (Apple Silicon + Intel).
2. Abre el `.dmg` y arrastra Sesamo a Aplicaciones.
3. El binario no va firmado con certificado de Apple Developer, asi que Gatekeeper lo bloquea la primera vez. Autorizalo con:

   ```bash
   xattr -cr /Applications/Sesamo.app
   ```

   (o clic derecho > Abrir, solo la primera vez)
4. Al arrancar pide la URL de tu servidor (p.ej. `https://vault.example.com`) y la recuerda para los siguientes arranques.

Cada release incluye `SHA256SUMS.txt` para verificar la descarga: `shasum -a 256 -c SHA256SUMS.txt --ignore-missing`.

### Extension de Chrome

1. Descarga `sesamo-extension-<version>.zip` desde Releases y descomprimelo.
2. Abre `chrome://extensions` y activa el **modo desarrollador**.
3. **Cargar extension sin empaquetar** y selecciona la carpeta descomprimida.

El mismo zip vale para subirlo al Chrome Web Store si se quiere distribuir firmada.

### Servidor (Docker)

La imagen es multi-arch (`linux/amd64` y `linux/arm64`): sirve para un servidor Linux x86, para ARM (Raspberry Pi, Graviton) y para Docker Desktop en Mac, donde Apple Silicon usa la variante arm64 nativa.

Despliegue completo con PostgreSQL incluido, usando el `docker-compose.yml` del repo:

```bash
git clone https://github.com/pmoncadaisla/maspassword.git && cd maspassword
JWT_SECRET=$(openssl rand -hex 32) docker compose up -d
```

La app queda en `http://localhost:8080` y las migraciones se aplican solas al arrancar. Variables del compose:

| Variable | Descripcion | Por defecto |
|----------|-------------|-------------|
| `JWT_SECRET` | Secreto para firmar JWT | — (obligatoria, sin default a proposito) |
| `DB_PASSWORD` | Password de PostgreSQL | `vault_pass` (cambialo) |
| `PORT` | Puerto publicado en el host | `8080` |
| `CORS_ORIGINS` | Origenes CORS permitidos | vacio |

Con una base de datos ya existente no hace falta compose:

```bash
docker run -d --name maspassword -p 8080:8080 \
  -e DATABASE_URL='postgres://user:pass@host:5432/vault_internal?sslmode=disable' \
  -e JWT_SECRET="$(openssl rand -hex 32)" \
  ghcr.io/pmoncadaisla/maspassword:latest
```

### Notas de produccion

- **HTTPS es obligatorio** salvo en `localhost`: el cifrado del cliente usa la API Web Crypto (`crypto.subtle`), que los navegadores solo exponen en contextos seguros. Pon el contenedor detras de un reverse proxy con TLS (Caddy, nginx, Traefik).
- Rotar `JWT_SECRET` invalida las sesiones activas, pero no afecta a los datos: estan cifrados con las claves de los usuarios, no con este secreto.
- Copia de seguridad = `pg_dump` de la base de datos. Todo lo sensible ya viaja y se guarda cifrado.
- La imagen corre como usuario no-root (uid 10001).

### Despliegue en GCP (Cloud Run + Cloud SQL)

Version minima con la instancia mas barata de Cloud SQL. Cloud Run no puede tirar directamente de `ghcr.io`, asi que la imagen se copia a Artifact Registry.

```bash
PROJECT=mi-proyecto REGION=europe-southwest1
gcloud config set project $PROJECT
gcloud services enable run.googleapis.com sqladmin.googleapis.com artifactregistry.googleapis.com

# Cloud SQL minimo (PostgreSQL 15)
gcloud sql instances create maspassword-db --database-version=POSTGRES_15 \
  --tier=db-f1-micro --region=$REGION
gcloud sql databases create vault_internal --instance=maspassword-db
gcloud sql users create vault_user --instance=maspassword-db --password='CAMBIA-ESTO'

# Copiar la imagen de GHCR a Artifact Registry
gcloud artifacts repositories create maspassword --repository-format=docker --location=$REGION
gcloud auth configure-docker $REGION-docker.pkg.dev
docker pull ghcr.io/pmoncadaisla/maspassword:latest
docker tag ghcr.io/pmoncadaisla/maspassword:latest \
  $REGION-docker.pkg.dev/$PROJECT/maspassword/maspassword:latest
docker push $REGION-docker.pkg.dev/$PROJECT/maspassword/maspassword:latest

# Desplegar conectando por socket de Cloud SQL
CONN="$PROJECT:$REGION:maspassword-db"
gcloud run deploy maspassword \
  --image=$REGION-docker.pkg.dev/$PROJECT/maspassword/maspassword:latest \
  --region=$REGION \
  --add-cloudsql-instances=$CONN \
  --set-env-vars="DATABASE_URL=postgres://vault_user:CAMBIA-ESTO@/vault_internal?host=/cloudsql/$CONN&sslmode=disable,JWT_SECRET=$(openssl rand -hex 32)" \
  --allow-unauthenticated
```

Cloud Run inyecta `PORT` y el servidor lo respeta; el TLS lo pone Cloud Run, con lo que el requisito de HTTPS para Web Crypto queda cubierto. Para produccion, mejor pasar los secretos con `--set-secrets` (Secret Manager) en vez de `--set-env-vars`, y restringir el acceso: `scripts/deploy-gcp.sh` automatiza este mismo despliegue con IAP nativo de Cloud Run (sin `--allow-unauthenticated`), que limita el acceso a las cuentas Google de la organizacion.

### Publicar una release

```bash
git tag v1.1.0 && git push origin v1.1.0
```

El workflow compila el `.dmg` universal, el zip de la extension y la imagen Docker multi-arch, y crea la Release con `SHA256SUMS.txt`. En cada pull request compila todo igualmente y deja los artefactos en la ejecucion del workflow, sin publicar nada.

Nota sobre GHCR: el primer push crea el paquete como privado. Para que `docker pull` funcione sin autenticacion hay que marcarlo como publico una vez en GitHub > Packages > `maspassword` > Package settings > Change visibility.

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
| DELETE | `/api/vaults/:id` | Eliminar boveda (propietario o admin del equipo) |
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
| `REDIRECT_ALL_TO` | Retira el despliegue: redirige (301) toda peticion a este origen, sin tocar la base de datos | — (desactivado) |

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
