# fluxcd_core

Builds and configures the `core` cluster — the platform tier of STP Labs
production systems, kept in its own repository so that changes here cannot reach the
staging or production clusters managed from `fluxcd`.

The cluster is three Proxmox guests, one pinned per hypervisor, running RKE2
with all three nodes as combined server + agent. Three is the floor: Rook-Ceph
needs three failure domains, and a separate agent tier does not fit the memory
budget.

## Layout

| Path | What it does |
|---|---|
| [`terraform/`](terraform/README.md) | Provisions the three guests on Proxmox. Owns all site topology. |
| [`ansible/`](ansible/README.md) | Turns those guests into an RKE2 cluster. |
| `.github/workflows/` | Lint, validate and test both layers on pull requests. |

Flux manifests are not here yet. When they land they will sit alongside these
two directories, not replace them.

## Order of operations

The layers are not independent — Terraform generates the inventory and
variables that Ansible consumes, so it must run first even when no
infrastructure has changed:

```
terraform apply          # provisions guests, writes ansible/inventory/*
ansible-playbook ...     # installs RKE2 onto them
```

Both generated files are gitignored. A fresh checkout has no inventory until
`terraform apply` has run once.

## Where the topology lives

No addresses, hostnames or account names appear anywhere in tracked source.
Site-specific values live in `terraform/terraform.tfvars`, which is gitignored,
and are committed only as `terraform/terraform.tfvars.sops.json` — encrypted
with age via SOPS, matching how the `fluxcd` and `flux_private` repositories
handle secrets.

Terraform then generates what Ansible needs:

```
terraform.tfvars (SOPS-encrypted, committed)
        │
        ├── ansible/inventory/core.ini                        (gitignored)
        └── ansible/inventory/group_vars/core/generated.yml   (gitignored)
```

Each generated file has a committed `.example` alongside it, so the shape stays
in version control and CI has something to validate against.

Losing the age key means losing the ability to decrypt the topology. It is
backed up outside this machine; keep it that way.

## Prerequisites

Both layers depend on credentials and trust material that are deliberately not
in this repository. Each directory's README lists its own; the short version:

- Proxmox API token, scoped rather than root
- The Proxmox cluster CA installed in the local trust store
- RustFS S3 credentials for Terraform remote state
- An age key for SOPS
- An RKE2 join token, supplied at run time

## Conventions carried from `fluxcd`

- SOPS with age for anything secret
- Terraform state in the internal RustFS bucket, one key per repository
- RKE2 versions pinned to match the rest of the estate

## Constraints worth knowing before you change anything

- **The guests carry the whole etcd quorum.** All three are control-plane
  members. Anything that restarts them in parallel takes the cluster down;
  `reboot_after_update = false` exists to stop Terraform doing exactly that.
- **The PVE firewall is enforcing** on all three guests with a `DROP` input
  policy. Reaching a new port means adding a rule first.
- **State lives on another cluster.** Terraform's backend is RustFS behind an
  ingress on `rpi-rke2`, so an outage there blocks all Terraform work here.

Each directory's README covers the rest.
