resource "proxmox_download_file" "ubuntu_noble" {
  for_each = toset(local.pve_nodes)

  node_name    = each.value
  content_type = "import"
  datastore_id = "local"

  file_name          = "noble-server-cloudimg-amd64-${local.image_build}.qcow2"
  url                = var.ubuntu_image_url
  checksum           = var.ubuntu_image_checksum
  checksum_algorithm = "sha256"

  overwrite_unmanaged = true
}

resource "proxmox_virtual_environment_vm" "core" {
  for_each = var.nodes

  name        = each.key
  vm_id       = each.value.vmid
  node_name   = each.value.pve_node
  description = "RKE2 server+agent, ${var.cluster_name} cluster. Managed by terraform in fluxcd_core; do not edit by hand."
  tags        = sort([var.cluster_name, "rke2", "terraform"])

  on_boot             = true
  started             = true
  reboot_after_update = false

  lifecycle {
    prevent_destroy = true
  }

  agent {
    enabled = coalesce(each.value.qemu_agent, var.qemu_agent_enabled)
  }

  boot_order = ["scsi0", "ide2"]

  cpu {
    cores = var.vcpu
    type  = "host"
  }

  memory {
    dedicated = var.memory_mib
    floating  = 0
  }

  scsi_hardware = "virtio-scsi-pci"

  disk {
    interface    = "scsi0"
    datastore_id = each.value.datastore
    import_from  = proxmox_download_file.ubuntu_noble[each.value.pve_node].id
    size         = var.os_disk_gib
    file_format  = "raw"
    discard      = "on"
    ssd          = true
  }

  disk {
    interface    = local.osd_interface
    datastore_id = each.value.datastore
    size         = var.osd_disk_gib
    file_format  = "raw"
    discard      = "on"
    ssd          = true
    backup       = false
  }

  network_device {
    bridge   = var.network_bridge
    vlan_id  = var.vlan_id
    model    = "virtio"
    firewall = var.firewall_enabled
  }

  initialization {
    datastore_id = each.value.datastore

    ip_config {
      ipv4 {
        address = each.value.ip_cidr
        gateway = var.gateway
      }
    }

    dns {
      domain  = var.search_domain
      servers = var.nameservers
    }

    user_account {
      username = var.guest_username
      keys     = local.ssh_public_keys
    }
  }

  operating_system {
    type = "l26"
  }

  bios = "ovmf"

  efi_disk {
    datastore_id = each.value.datastore
    file_format  = "raw"
    type         = "4m"
  }

  serial_device {}
}
