locals {
  ssh_public_keys = coalesce(
    var.ssh_public_keys,
    [trimspace(file(pathexpand("${var.proxmox_ssh_private_key_file}.pub")))],
  )

  pve_nodes   = distinct([for n in var.nodes : n.pve_node])
  image_build = element(split("/", var.ubuntu_image_url), 4)

  guest_ips = {
    for name, vm in proxmox_virtual_environment_vm.core :
    name => split("/", vm.initialization[0].ip_config[0].ipv4[0].address)[0]
  }

  ansible_inventory = join("\n", concat(
    ["[${var.cluster_name}_servers]"],
    [for name, ip in local.guest_ips :
      format("%s\tansible_host=%s\trke2_type=server", name, ip)
    ],
    ["", "[${var.cluster_name}:children]", "${var.cluster_name}_servers", ""],
  ))

  osd_interface = "scsi1"
  osd_device    = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-${local.osd_interface}"
}
