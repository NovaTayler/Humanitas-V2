output "cloud_run_url" { value = google_cloud_run_service.drops_service.status[0].url }
output "sql_connection" { value = google_sql_database_instance.dropshipping_db.connection_name }
