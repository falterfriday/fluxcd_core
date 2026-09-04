resource "local_file" "ansible_inventory" {
  filename        = var.ansible_inventory_path
  content         = local.ansible_inventory
  file_permission = "0640"
}
