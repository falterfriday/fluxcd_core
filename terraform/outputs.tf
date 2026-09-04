output "nodes" {
  description = "Guest placement and addressing, read back from the managed VMs rather than from input variables."
  value = {
    for name, vm in proxmox_virtual_environment_vm.core : name => {
      vmid       = vm.vm_id
      pve_node   = vm.node_name
      ip         = local.guest_ips[name]
      datastore  = vm.initialization[0].datastore_id
      vcpu       = vm.cpu[0].cores
      memory_gib = vm.memory[0].dedicated / 1024
    }
  }
}

output "ansible_inventory" {
  description = "Generated inventory. Written to var.ansible_inventory_path on apply; this output is for inspection."
  value       = local.ansible_inventory
}

output "ansible_inventory_path" {
  description = "Path of the generated inventory file."
  value       = local_file.ansible_inventory.filename
}

output "osd_devices" {
  description = "Stable by-id paths Rook-Ceph will claim. Must be empty before the CephCluster is applied."
  value       = { for name, _ in proxmox_virtual_environment_vm.core : name => local.osd_device }
}
