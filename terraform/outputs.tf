output "nodes" {
  description = "Guest placement and addressing for x-checking against the Ansible inventory"
  value = {
    for name, cfg in var.nodes : name => {
      vmid       = cfg.vmid
      pve_node   = cfg.pve_node
      ip         = split("/", cfg.ip_cidr)[0]
      datastore  = cfg.datastore
      vcpu       = var.vcpu
      memory_gib = var.memory_mib / 1024
    }
  }
}

output "ansible_inventory" {
  description = "Paste into /etc/ansible/hosts"
  value = join("\n", concat(
    ["[${var.cluster_name}_servers]"],
    [for name, cfg in var.nodes :
      format("%s\tansible_host=%s\trke2_type=server", name, split("/", cfg.ip_cidr)[0])
    ],
    ["", "[${var.cluster_name}:children]", "${var.cluster_name}_servers"],
  ))
}

output "osd_devices" {
  description = "Stable by-id paths Rook-Ceph will claim. Must be empty before the CephCluster is applied."
  value       = { for name, _ in var.nodes : name => local.osd_device }
}
