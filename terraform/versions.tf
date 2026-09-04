terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.111.1"
    }

    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}
