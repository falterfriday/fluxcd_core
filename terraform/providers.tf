provider "proxmox" {
  endpoint  = var.proxmox_endpoint
  api_token = var.proxmox_api_token
  insecure  = var.proxmox_insecure
  min_tls   = var.proxmox_min_tls

  ssh {
    agent       = false
    username    = var.proxmox_ssh_user
    private_key = file(pathexpand(var.proxmox_ssh_private_key_file))

    dynamic "node" {
      for_each = var.pve_hosts
      content {
        name    = node.key
        address = node.value
      }
    }
  }
}
