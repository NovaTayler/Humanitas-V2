variable "gcp_project" { type = string }
variable "region" { type = string, default = "us-central1" }
variable "db_password" { type = string, sensitive = true }
variable "telegram_token" { type = string, sensitive = true }
variable "telegram_chat_id" { type = string, sensitive = true }
variable "webhook_secret" { type = string, sensitive = true }
variable "paypal_client_id" { type = string, sensitive = true }
variable "paypal_secret" { type = string, sensitive = true }
variable "twilio_sid" { type = string, sensitive = true }
variable "twilio_api_key" { type = string, sensitive = true }
variable "captcha_api_key" { type = string, sensitive = true }
variable "cj_api_key" { type = string, sensitive = true }
variable "cj_secret_key" { type = string, sensitive = true }
