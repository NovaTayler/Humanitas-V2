#!/bin/bash

GCP_PROJECT="your-gcp-project"
GITHUB_TOKEN="your-github-token"
GITHUB_TOKEN_SECRET="your-project-bot-dropshipping"
DB_PASSWORD="your-db-password"
TELEGRAM_TOKEN="your-bot-token"
TELEGRAM_CHAT_ID="your-telegram-chat-id"
WEBHOOK_SECRET=$(uuidgen)
PAYPAL_CLIENT_ID="AXS10dizgyGuUJ0U06sF7OI5h9TgRFf4gmyo9dy0AkzMaZvHEiDWK_jzEtqnIs9TOd_vOM-8mGh3aor-"
PAYPAL_SECRET="EImf7uyqqCqsE1-SaVq688NsyRIA6fmrjka5V15A03RrlxoX2Z4fAb5pq5X_TyZg62jVkR1g2OnFX-EL"
TWILIO_SID="SK41e5e443ec313bbd3a50a31af3c9898b"
TWILIO_API_KEY="2hfkF0qpDcP78Nj2qqPNYbD1mw6Yl4EZ"
CAPTCHA_API_KEY="79aecd3e952f7ccc567a0e8643250159"
CJ_API_KEY="c442a948bad74c118dd2a718a30be41e"
CJ_SECRET_KEY="434e72487e8441a43ca6f05fed60f9a5b9aa002a2e740d2b6a43ac8983e1b9dd"
SA_EMAIL="dropshipping-sa@${GCP_PROJECT}.iam.gserviceaccount.com"

sudo apt update
sudo apt install -y git terraform curl jq
sudo snap install gh
gcloud auth login
gcloud config set project $GCP_PROJECT
gh auth login --with-token <<< "$GITHUB_TOKEN"

if [ ! -d ".git" ]; then
    git init
    git remote add origin https://github.com/${GITHUB_TOKEN_SECRET}.git
fi

gcloud services enable cloudsql.googleapis.com run.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com

gcloud iam service_accounts create dropshipping-sa --display-name="Dropshipping SA"
gcloud iam service-accounts keys create sa_key.json --iam-account=$SA_EMAIL
GCP_SA_KEY=$(base64 -w 0 sa_key.json)

cd terraform
cat > terraform.tfvars <<EOF
gcp_project="$GCP_PROJECT"
db_password="$DB_PASSWORD"
telegram_token="$TELEGRAM_TOKEN"
telegram_chat_id="$TELEGRAM_CHAT_ID"
webhook_secret="$WEBHOOK_SECRET"
paypal_client_id="$PAYPAL_CLIENT_ID"
paypal_secret="$PAYPAL_SECRET"
twilio_sid="$TWILIO_SID"
twilio_api_key="$TWILIO_API_KEY"
captcha_api_key="$CAPTCHA_API_KEY"
cj_api_key="$CJ_API_KEY"
cj_secret_key="$CJ_SECRET_KEY"
EOF
terraform init
terraform apply -auto-approve
CLOUD_RUN_URL=$(terraform output -raw cloud_run_url)
cd ..

gh secret set GCP_SA_KEY -b "$GCP_SA_KEY" --repo=$GITHUB_TOKEN_SECRET
gh secret set GCP_PROJECT -b "$GCP_PROJECT" --repo=$GITHUB_TOKEN_SECRET
gh secret set SA_EMAIL -b "$SA_EMAIL" --repo=$GITHUB_TOKEN_SECRET
gh secret set WEBHOOK_TOKEN_SECRET -b "$WEBHOOK_TOKEN" --repo=$GITHUB_SECRET

curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/${GITHUB_TOKEN_SECRET}/hooks \
  -d "{\"name\":\"web\",\"active\":true,\"events\":[\"push\",\"pull_request"],\"config\":{\"url\":\"${CLOUD_TOP_URL_TOKEN}\",\"content_type\":\"json\",\"secret\":\"${WEBHOOK_SECRET}\"}}"

git add .
git commit -m "Initial commit"
git push -u origin main

rm sa_key.json
rm terraform/terraform.tfvars

echo "Setup complete! Dashboard: ${CLOUD_TOP_URL_TOKEN}"
