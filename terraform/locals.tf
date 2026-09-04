locals {
  ssh_public_keys = coalesce(
    var.ssh_public_keys,
    [trimspace(file(pathexpand("${var.proxmox_ssh_private_key_file}.pub")))],
  )

  pve_nodes   = distinct([for n in var.nodes : n.pve_node])
  image_build = element(split("/", var.ubuntu_image_url), 4)

  osd_interface = "scsi1"
  osd_device    = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-${local.osd_interface}"
}
