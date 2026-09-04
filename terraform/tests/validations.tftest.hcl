mock_provider "proxmox" {}
mock_provider "local" {}

variables {
  proxmox_endpoint             = "https://pve.example:8006/"
  pve_hosts                    = { "pve-0" = "10.0.0.10", "pve-1" = "10.0.0.11" }
  proxmox_ssh_user             = "svcuser"
  guest_username               = "svcuser"
  proxmox_ssh_private_key_file = "~/.ssh/id_ecdsa"
  network_bridge               = "vmbr0"
  vlan_id                      = 130
  gateway                      = "10.0.0.1"
  nameservers                  = ["10.0.0.53"]
  search_domain                = "example.test"
  proxmox_api_token            = "test@pam!test=00000000-0000-0000-0000-000000000000"
  ssh_public_keys              = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test@test"]

  nodes = {
    "a" = { vmid = 101, pve_node = "pve-0", datastore = "d0", ip_cidr = "10.0.0.21/24" }
    "b" = { vmid = 102, pve_node = "pve-1", datastore = "d1", ip_cidr = "10.0.0.22/24" }
  }
}

run "rejects_two_guests_on_one_hypervisor" {
  command = plan
  variables {
    nodes = {
      "a" = { vmid = 101, pve_node = "pve-0", datastore = "d0", ip_cidr = "10.0.0.21/24" }
      "b" = { vmid = 102, pve_node = "pve-0", datastore = "d0", ip_cidr = "10.0.0.22/24" }
    }
  }
  expect_failures = [var.nodes]
}

run "rejects_duplicate_vmid" {
  command = plan
  variables {
    nodes = {
      "a" = { vmid = 101, pve_node = "pve-0", datastore = "d0", ip_cidr = "10.0.0.21/24" }
      "b" = { vmid = 101, pve_node = "pve-1", datastore = "d1", ip_cidr = "10.0.0.22/24" }
    }
  }
  expect_failures = [var.nodes]
}

run "rejects_duplicate_ip" {
  command = plan
  variables {
    nodes = {
      "a" = { vmid = 101, pve_node = "pve-0", datastore = "d0", ip_cidr = "10.0.0.21/24" }
      "b" = { vmid = 102, pve_node = "pve-1", datastore = "d1", ip_cidr = "10.0.0.21/24" }
    }
  }
  expect_failures = [var.nodes]
}

run "rejects_node_missing_from_pve_hosts" {
  command = plan
  variables {
    nodes = {
      "a" = { vmid = 101, pve_node = "pve-9", datastore = "d0", ip_cidr = "10.0.0.21/24" }
    }
  }
  expect_failures = [var.nodes]
}

run "rejects_untagged_vlan" {
  command = plan
  variables { vlan_id = 0 }
  expect_failures = [var.vlan_id]
}
