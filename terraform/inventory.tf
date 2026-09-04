resource "local_file" "ansible_inventory" {
  filename        = var.ansible_inventory_path
  content         = local.ansible_inventory
  file_permission = "0640"
}

resource "local_file" "ansible_group_vars" {
  filename        = var.ansible_group_vars_path
  content         = "---\n${yamlencode(local.ansible_group_vars)}"
  file_permission = "0600"
}
