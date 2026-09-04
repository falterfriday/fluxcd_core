resource "proxmox_virtual_environment_cluster_firewall" "this" {
  enabled       = var.firewall_enabled
  input_policy  = "ACCEPT"
  output_policy = "ACCEPT"
}

resource "proxmox_virtual_environment_firewall_ipset" "core_nodes" {
  name    = "core-nodes"
  comment = "core cluster guests"

  dynamic "cidr" {
    for_each = local.guest_ips
    content {
      name    = cidr.value
      comment = cidr.key
    }
  }
}

resource "proxmox_virtual_environment_cluster_firewall_security_group" "core" {
  name    = "core-cluster"
  comment = "RKE2 servers and Ceph. Managed by terraform in fluxcd_core."

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "2379:2381"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "etcd client, peer and metrics"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "6443"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "Kubernetes API between nodes"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "9345"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "RKE2 supervisor"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "10250"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "kubelet"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "10256"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "kube-proxy health"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "udp"
    dport   = "4789"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "Calico VXLAN"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "5473"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "Calico Typha"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "3300"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "Ceph mon v2"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "6789"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "Ceph mon v1"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "6800:7300"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "Ceph OSD"
  }

  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "icmp"
    source  = "+${proxmox_virtual_environment_firewall_ipset.core_nodes.name}"
    comment = "ICMP between cluster nodes"
  }

  dynamic "rule" {
    for_each = var.firewall_admin_sources
    content {
      type    = "in"
      action  = "ACCEPT"
      proto   = "tcp"
      dport   = "22"
      source  = rule.value
      comment = "SSH from admin"
    }
  }

  dynamic "rule" {
    for_each = var.firewall_admin_sources
    content {
      type    = "in"
      action  = "ACCEPT"
      proto   = "tcp"
      dport   = "6443"
      source  = rule.value
      comment = "Kubernetes API from admin"
    }
  }

  dynamic "rule" {
    for_each = var.firewall_admin_sources
    content {
      type    = "in"
      action  = "ACCEPT"
      proto   = "icmp"
      source  = rule.value
      comment = "ICMP from admin"
    }
  }

  dynamic "rule" {
    for_each = var.ingress_sources
    content {
      type    = "in"
      action  = "ACCEPT"
      proto   = "tcp"
      dport   = "80"
      source  = rule.value
      comment = "ingress-nginx hostPort"
    }
  }

  dynamic "rule" {
    for_each = var.ingress_sources
    content {
      type    = "in"
      action  = "ACCEPT"
      proto   = "tcp"
      dport   = "443"
      source  = rule.value
      comment = "ingress-nginx hostPort"
    }
  }
}

resource "proxmox_virtual_environment_firewall_options" "core" {
  for_each = proxmox_virtual_environment_vm.core

  node_name = each.value.node_name
  vm_id     = each.value.vm_id

  enabled       = var.firewall_enabled
  input_policy  = "DROP"
  output_policy = "ACCEPT"
  dhcp          = false
  macfilter     = true
  ndp           = false
}

resource "proxmox_virtual_environment_firewall_rules" "core" {
  for_each = proxmox_virtual_environment_vm.core

  node_name = each.value.node_name
  vm_id     = each.value.vm_id

  rule {
    security_group = proxmox_virtual_environment_cluster_firewall_security_group.core.name
    comment        = "core-cluster policy"
  }
}
