variable "ansible_inventory_path" {
  description = "Where the generated Ansible inventory is written. Point at the Ansible repo to consume it directly"
  type        = string
  default     = "inventory/core.ini"
}

variable "cluster_name" {
  description = "Cluster name for tags and the Ansible inventory"
  type        = string
  default     = "core"
}

variable "firewall_admin_sources" {
  description = "CIDRs allowed to reach SSH and the Kubernetes API on the guests. Empty emits no admin rules"
  type        = list(string)
  default     = []
}

variable "firewall_enabled" {
  description = "Master switch for the PVE firewall. False stages the rules without enforcing"
  type        = bool
  default     = false
}

variable "gateway" {
  description = "Default gateway on the guest VLAN"
  type        = string
}

variable "guest_username" {
  description = "Login account created in each guest by cloud-init."
  type        = string
}

variable "ingress_sources" {
  description = "CIDRs allowed to reach ingress-nginx hostPorts 80/443. Empty emits no ingress rules"
  type        = list(string)
  default     = []
}

variable "memory_mib" {
  description = "RAM per node in MiB"
  type        = number
  default     = 16384
}

variable "nameservers" {
  description = "DNS resolvers for the guests"
  type        = list(string)
}

variable "network_bridge" {
  description = "VLAN-aware bridge on the PVE nodes"
  type        = string
}

variable "nodes" {
  description = "One guest per physical host, pinned"
  type = map(object({
    vmid       = number
    pve_node   = string
    datastore  = string
    ip_cidr    = string
    qemu_agent = optional(bool)
  }))
  validation {
    condition     = length(distinct([for n in var.nodes : n.pve_node])) == length(var.nodes)
    error_message = "Each guest must sit on its own PVE host, or Ceph's host failure domain becomes fiction"
  }

  validation {
    condition     = length(distinct([for n in var.nodes : n.vmid])) == length(var.nodes)
    error_message = "Duplicate vmid. PVE rejects the second create midway through the apply"
  }

  validation {
    condition     = length(distinct([for n in var.nodes : n.ip_cidr])) == length(var.nodes)
    error_message = "Duplicate ip_cidr. This applies without error and silently collides on the wire"
  }

  validation {
    condition     = alltrue([for n in var.nodes : contains(keys(var.pve_hosts), n.pve_node)])
    error_message = "Every nodes[*].pve_node must have a matching entry in pve_hosts"
  }
}

variable "os_disk_gib" {
  description = "Boot disk size in GiB"
  type        = number
  default     = 100
}

variable "osd_disk_gib" {
  description = "Raw second disk presented as /dev/sdb for a single Ceph OSD"
  type        = number
  default     = 200
}

variable "proxmox_api_token" {
  description = "Proxmox API token as user@realm!tokenid=uuid. Leave null and export PROXMOX_VE_API_TOKEN instead"
  type        = string
  sensitive   = true
  default     = null
}

variable "proxmox_endpoint" {
  description = "Proxmox VE API endpoint"
  type        = string
}

variable "proxmox_insecure" {
  description = "Skip TLS verification against the PVE API"
  type        = bool
  default     = false
}

variable "proxmox_min_tls" {
  description = "Minimum TLS version negotiated with the PVE API"
  type        = string
  default     = "1.3"
}

variable "proxmox_ssh_private_key_file" {
  description = "Private key authorised for proxmox_ssh_user on all PVE nodes"
  type        = string
}

variable "proxmox_ssh_user" {
  description = "SSH user on the PVE nodes, used by the provider for disk import"
  type        = string
}

variable "pve_hosts" {
  description = "PVE hypervisor name to management address, used by the provider for SSH disk import"
  type        = map(string)
}

variable "qemu_agent_enabled" {
  description = "Whether the VMs present a QEMU guest agent channel. Must be false on the initial create, before Ansible installs qemu-guest-agent"
  type        = bool
  default     = true
}

variable "search_domain" {
  description = "Guest DNS search domain"
  type        = string
}

variable "ssh_public_keys" {
  description = "Authorised keys for the guest login account"
  type        = list(string)
  default     = null
}

variable "ubuntu_image_checksum" {
  description = "SHA256 of ubuntu_image_url. Update both together"
  type        = string
  default     = "d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30"
}

variable "ubuntu_image_url" {
  description = "Ubuntu 24.04 LTS cloud image"
  type        = string
  default     = "https://cloud-images.ubuntu.com/noble/20260826/noble-server-cloudimg-amd64.img"
}

variable "vcpu" {
  description = "vCPU per node"
  type        = number
  default     = 6
}

variable "vlan_id" {
  description = "Guest VLAN"
  type        = number

  validation {
    condition     = var.vlan_id >= 1 && var.vlan_id <= 4094
    error_message = "vlan_id must be 1-4094. 0 is untagged, which puts guests on the bridge native VLAN alongside the hypervisors"
  }
}
