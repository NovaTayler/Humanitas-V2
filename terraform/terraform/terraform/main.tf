provider "google" {
  project = var.gcp_project
  region  = var.region
}

resource "google_sql_database_instance" "drops_db" {
  name             = "dropshipping-db"
  database_version = "POSTGRES_14"
  region           = var.region
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      authorized_networks { value = "0.0.0.0/0" }
    }
  }
}

resource "google_sql_database" "dropshipping" {
  name     = "dropshipping"
  instance = google_sql_database_instance.drops_db.name
}

resource "google_sql_user" "postgres" {
  name     = "postgres"
  instance = google_sql_database_instance.drops_db.name
  password = var.db_password
}

resource "google_artifact_registry_repository" "drops_repo" {
  location      = var.region
  repository_id = "dropshipping-repo"
  format        = "DOCKER"
}

resource "google_service_account" "drops_sa" {
  account_id   = "dropshipping-sa"
  display_name = "Dropshipping SA"
}

resource "google_project_iam_member" "sa_roles" {
  for_each = toset([
    "roles/cloudsql.client",
    "roles/run.admin",
    "roles/artifactregistry.writer",
    "roles/secretmanager.secretAccessor",
  ])
  project = var.gcp_project
  role    = each.value
  member  = "serviceAccount:${google_service_account.drops_sa.email}"
}

resource "google_secret_manager_secret" "secrets" {
  for_each = {
    db_password      = var.db_password
    telegram_token     = var.telegram_token
    telegram_chat_id   = var.telegram_chat_id
    webhook_secret     = var.webhook_secret
    paypal_client_id    = var.paypal_client_id
    paypal_secret         = var.paypal_secret
    twilio_sid        = var.twilio_sid
    twilio_api_key     = var.twilio_api_key
    captcha_api_key    = var.captcha_api_key
    cj_api_key         = var.cj_api_key
    cj_secret_key      = var.cj_secret_key
  }
  secret_id = each.key
  replication { auto {} }
}

resource "google_secret_manager_secret_version" "secret_versions" {
  for_each    = google_secret_manager_secret.secrets
  secret      = each.value.id
  secret_data = each.value.secret_data
}

resource "google_cloud_run_service" "drops_service" {
  name     = "dropshipping-bot"
  location = var.region

  template {
    spec {
      containers {
        image = "us-central1-docker.pkg.dev/${var.gcp_project}/dropshipping-bot/dropshipping-bot:latest"
        env {
          name  = "DB_USER"
          value = "postgres"
        }
        env {
          name  = "DB_NAME"
          value = "dropshipping"
        }
        env {
          name  = "DB_HOST"
          value = "/cloudsql/${google_sql_database_instance.drops_db.connection_name}"
        }
        env {
          name  = "GCP_PROJECT"
          value = var.gcp_project
        }
        env {
          name  = "SERVICE_URL"
          value = "https://${google_cloud_run_service.drops_service.status[0].url}"
        }
        env {
          name  = "PAYPAL_EMAIL"
          value = "jefftayler@live.ca"
        }
        env {
          name  = "BTC_WALLET"
          value = "bc1q3mwnpa8ndqznyylgtgn8p329qh7g7vhzukdl5t"
        }
        env {
          name  = "ETH_WALLET"
          value = "0x7A51478775722a4faa72b966134a4c47BF6BA60E"
        }
        dynamic "env" {
          for_each = {
            "DB_PASSWORD"      = "db_password"
            "TELEGRAM_BOT_TOKEN" = "telegram_token"
            "TELEGRAM_CHAT_ID"  = "telegram_chat_id"
            "WEBHOOK_SECRET"    = "webhook_secret"
            "PAYPAL_CLIENT_ID"   = "paypal_client_id"
            "PAYPAL_SECRET"        = "paypal_secret"
            "TWILIO_SID"         = "twilio_sid"
            "TWILIO_API_KEY"     = "twilio_api_key"
            "CAPTCHA_API_KEY"    = "captcha_api_key"
            "CJ_API_KEY"         = "cj_api_key"
            "CJ_SECRET_KEY"      = "cj_secret_key"
          }
          content {
            name = env.key
            value_from {
              secret_key_ref {
                name = google_secret_manager_secret.secrets[env.value].secret_id
                key  = "latest"
              }
            }
          }
        }
      }
      service_account_name = google_service_account.drops_sa.email
    }
    metadata {
      annotations = {
        "run.googleapis.com/cloudsql-instances" = google_sql_database_instance.drops_db.connection_name
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}

resource "google_cloud_run_service_iam_policy" "noauth" {
  location = google_cloud_run_service.drops_service.location
  project  = google_cloud_run_service.drops_service.project
  service  = google_cloud_run_service.drops_service.name

  policy_data = jsonencode({
    bindings = [{ role = "roles/run.invoker", members = ["allUsers"] }]
  })
}
