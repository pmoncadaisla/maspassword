# Sésamo (repo `maspassword`) — instrucciones para Claude

El producto se llama **Sésamo** ("sesamo" donde no se puede acentuar: nombres de fichero, bundle macOS, artefactos). Los identificadores internos (módulo Go, imagen Docker, servicio Cloud Run, paquetes `com.maspassword.*`) conservan `maspassword`.

## Al terminar trabajo: release + despliegue

Siempre que terminemos algo y esté mergeado en `main`, se publica release en GitHub y se despliega en Cloud Run. Las dos cosas, en ese orden.

1. **Release en GitHub**: crear y pushear un tag semántico (el último: `git tag --sort=-v:refname | head -1`):

   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

   El workflow `release.yml` ejecuta los tests, compila el `.dmg`, el zip de la extensión y la imagen Docker multi-arch, y publica la Release. Esperar a que acabe en verde: `gh run watch`.

2. **Desplegar en Cloud Run** (proyecto `mm-test-pmoncada`, región `europe-southwest1`, servicio `maspassword`). Se construye con Cloud Build desde el código del tag y se despliega solo la imagen; la tag de imagen en Artifact Registry va sin `v` (ej. `0.2.0`):

   ```bash
   IMG=europe-southwest1-docker.pkg.dev/mm-test-pmoncada/maspassword/maspassword:X.Y.Z
   gcloud builds submit --config cloudbuild.yaml --region=europe-southwest1 \
     --substitutions "_IMAGE=${IMG},_VERSION=vX.Y.Z"
   gcloud run deploy maspassword --region=europe-southwest1 --image="${IMG}"
   ```

   `gcloud run deploy --image` conserva las env vars y la configuración de la revisión anterior (Cloud SQL, IAP, Mailgun). No usar `scripts/deploy-gcp.sh` para redespliegues: es para crear la infraestructura desde cero y rota secretos si no encuentra `.db-password`/`.jwt-secret` en el directorio.

3. **Verificar**: `curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" <URL>/auth/mode` debe devolver la versión nueva.

Antes de desplegar cambios de frontend, subir `CACHE_NAME` en `web/sw.js`; si no, los clientes con la PWA instalada siguen sirviendo los assets viejos.
