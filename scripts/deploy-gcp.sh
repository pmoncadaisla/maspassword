#!/bin/bash
set -euo pipefail

# ============================================================
# Deploy maspassword to Google Cloud Run + CloudSQL
# IAP is enabled natively on Cloud Run (no Load Balancer needed)
# Project: mm-test-pmoncada | Region: europe-southwest1
# ============================================================

PROJECT="mm-test-pmoncada"
REGION="europe-southwest1"
SERVICE="maspassword"
DB_INSTANCE="maspassword-db"
DB_NAME="vault_internal"
DB_USER="vault_user"
DB_TIER="db-f1-micro"
AR_REPO="${SERVICE}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${AR_REPO}/${SERVICE}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

step() { echo -e "\n${GREEN}=== $1 ===${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }

# ---- Pre-flight checks ----
step "Pre-flight checks"
gcloud config set project "${PROJECT}"
echo "Project: $(gcloud config get-value project)"
echo "Region:  ${REGION}"

# ---- 1. Enable APIs ----
step "1/6 Enabling APIs"
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  iap.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  --quiet

# ---- 2. CloudSQL ----
step "2/6 CloudSQL instance"
if gcloud sql instances describe "${DB_INSTANCE}" --quiet 2>/dev/null; then
  echo "Instance ${DB_INSTANCE} already exists, skipping."
else
  echo "Creating CloudSQL instance (this takes a few minutes)..."
  gcloud sql instances create "${DB_INSTANCE}" \
    --database-version=POSTGRES_15 \
    --tier="${DB_TIER}" \
    --region="${REGION}" \
    --quiet
fi

# Database
if gcloud sql databases describe "${DB_NAME}" --instance="${DB_INSTANCE}" --quiet 2>/dev/null; then
  echo "Database ${DB_NAME} already exists."
else
  gcloud sql databases create "${DB_NAME}" --instance="${DB_INSTANCE}" --quiet
fi

# User (generate password if first run)
DB_PASS_FILE=".db-password"
if [ -f "${DB_PASS_FILE}" ]; then
  DB_PASS=$(cat "${DB_PASS_FILE}")
  echo "Using existing DB password from ${DB_PASS_FILE}"
else
  DB_PASS=$(openssl rand -base64 24)
  echo "${DB_PASS}" > "${DB_PASS_FILE}"
  chmod 600 "${DB_PASS_FILE}"
  echo "Generated DB password (saved to ${DB_PASS_FILE})"
fi

# Create or update user
if gcloud sql users list --instance="${DB_INSTANCE}" --format="value(name)" | grep -q "^${DB_USER}$"; then
  gcloud sql users set-password "${DB_USER}" \
    --instance="${DB_INSTANCE}" \
    --password="${DB_PASS}" --quiet
else
  gcloud sql users create "${DB_USER}" \
    --instance="${DB_INSTANCE}" \
    --password="${DB_PASS}" --quiet
fi

CONNECTION_NAME=$(gcloud sql instances describe "${DB_INSTANCE}" --format="value(connectionName)")
echo "Connection name: ${CONNECTION_NAME}"

# ---- 3. JWT Secret ----
step "3/6 JWT secret"
JWT_SECRET_FILE=".jwt-secret"
if [ -f "${JWT_SECRET_FILE}" ]; then
  JWT_SECRET=$(cat "${JWT_SECRET_FILE}")
  echo "Using existing JWT secret from ${JWT_SECRET_FILE}"
else
  JWT_SECRET=$(openssl rand -base64 32)
  echo "${JWT_SECRET}" > "${JWT_SECRET_FILE}"
  chmod 600 "${JWT_SECRET_FILE}"
  echo "Generated JWT secret (saved to ${JWT_SECRET_FILE})"
fi

# ---- 4. Artifact Registry + Build ----
step "4/6 Artifact Registry + Building container image"
if gcloud artifacts repositories describe "${AR_REPO}" --location="${REGION}" --quiet 2>/dev/null; then
  echo "Artifact Registry repo ${AR_REPO} already exists."
else
  gcloud artifacts repositories create "${AR_REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="maspassword container images" \
    --quiet
fi
# cloudbuild.yaml enables BuildKit, required by the multi-arch Dockerfile.
gcloud builds submit --config cloudbuild.yaml \
  --substitutions "_IMAGE=${IMAGE}" --region="${REGION}" --quiet

# ---- 5. Service Account + Deploy to Cloud Run ----
step "5/6 Deploying to Cloud Run"
SA_NAME="${SERVICE}-sa"
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "${SA_EMAIL}" --quiet 2>/dev/null; then
  echo "Service account ${SA_EMAIL} already exists."
else
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="maspassword Cloud Run SA" \
    --quiet
  # Grant CloudSQL client role
  gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/cloudsql.client" \
    --condition=None \
    --quiet
fi

DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@/${DB_NAME}?host=/cloudsql/${CONNECTION_NAME}&sslmode=disable"
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT}" --format="value(projectNumber)")
IAP_AUDIENCE="/projects/${PROJECT_NUMBER}/locations/${REGION}/services/${SERVICE}"

gcloud run deploy "${SERVICE}" \
  --image="${IMAGE}" \
  --region="${REGION}" \
  --platform=managed \
  --service-account="${SA_EMAIL}" \
  --add-cloudsql-instances="${CONNECTION_NAME}" \
  --set-env-vars="\
DATABASE_URL=${DATABASE_URL},\
JWT_SECRET=${JWT_SECRET},\
IAP_ENABLED=true,\
IAP_AUDIENCE=${IAP_AUDIENCE}" \
  --no-allow-unauthenticated \
  --min-instances=0 \
  --max-instances=3 \
  --quiet

SERVICE_URL=$(gcloud run services describe "${SERVICE}" --region="${REGION}" --format="value(status.url)")

# ---- Done ----
step "6/6 Deployment complete!"
echo ""
echo "  Cloud Run:    ${SERVICE_URL}"
echo "  IAP Audience: ${IAP_AUDIENCE}"
echo ""
echo "Next steps:"
echo "  1. Enable IAP on the Cloud Run service in the console if not already done"
echo "     (Cloud Run > Service > Security > IAP toggle)"
echo "  2. Configure OAuth consent screen if not done:"
echo "     https://console.cloud.google.com/apis/credentials/consent?project=${PROJECT}"
echo "  3. Grant IAP access to users:"
echo "     gcloud iap web add-iam-policy-binding --resource-type=cloud-run --service=${SERVICE} --region=${REGION} --member=user:EMAIL --role=roles/iap.httpsResourceAccessor"
echo ""
warn "Secrets stored locally in .db-password and .jwt-secret (gitignored)."
