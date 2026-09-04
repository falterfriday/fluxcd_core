# core cluster — Terraform

Provisions the three `core-srv-*` guests on Proxmox that become the `core` RKE2
cluster. One guest per hypervisor, pinned.

Everything below is a prerequisite that lives **outside this repo**. None of it
is discoverable from the code, which is why it is written down here.

## Prerequisites

| What | Where | Notes |
|---|---|---|
| Proxmox API token | `~/.proxmox` (mode 600) | `export PROXMOX_VE_API_TOKEN="$(tr -d '\n' < ~/.proxmox)"` |
| RustFS state credentials | `~/.aws/credentials` (mode 600) | S3 backend; not in this repo |
| PVE cluster CA | `/usr/local/share/ca-certificates/pve-root-ca.crt` | Required — `proxmox_insecure` is `false` |
| age key for SOPS | `~/.ssh/core-cluster.agekey` (mode 600) | `export SOPS_AGE_KEY_FILE=~/.ssh/core-cluster.agekey` |
| Terraform | >= 1.10.0 | `use_lockfile` in the S3 backend needs 1.10+ |

### Trusting the PVE CA

The API presents a certificate from the cluster's own CA. Its SAN already covers
the endpoint IP, so only the CA needs installing:

```bash
ssh -t ansible@<pve-host> 'sudo cat /etc/pve/pve-root-ca.pem' > pve-root-ca.pem
sudo cp pve-root-ca.pem /usr/local/share/ca-certificates/pve-root-ca.crt
sudo update-ca-certificates
openssl s_client -connect <pve-host>:8006 </dev/null 2>&1 | grep 'Verify return code'
```

### API token privileges

The token is scoped, not root. It needs every write privilege **and its read
counterpart** — omitting a read privilege makes Terraform believe resources have
been deleted and plan to recreate live VMs:

```
Sys.Audit, Sys.Modify
VM.Audit, VM.Allocate, VM.PowerMgmt, VM.Console, VM.GuestAgent.Audit
VM.Config.{CDROM,CPU,Cloudinit,Disk,HWType,Memory,Network,Options}
Datastore.Audit, Datastore.AllocateSpace
```

`Sys.Audit` is required for `query-url-metadata`, which the image download
resource calls; without it plans emit a misleading "remote file doesn't exist"
warning.

## First run

```bash
export SOPS_AGE_KEY_FILE=~/.ssh/core-cluster.agekey
sops -d --input-type json --output-type binary terraform.tfvars.sops.json > terraform.tfvars

export PROXMOX_VE_API_TOKEN="$(tr -d '\n' < ~/.proxmox)"
terraform init
terraform plan
```

`terraform.tfvars` holds the token and the site topology and is gitignored.
`terraform.tfvars.sops.json` is the committed, encrypted copy — re-encrypt it
after any change:

```bash
sops -e --input-type binary --output-type json terraform.tfvars > terraform.tfvars.sops.json
```

## Building a node from scratch

The guest agent bootstrap is two-phase and the order matters. The Ubuntu cloud
image ships no `qemu-guest-agent`, so creating with the agent enabled makes the
provider block for its full 15-minute timeout per VM:

```bash
terraform apply -var qemu_agent_enabled=false   # create
<ansible RKE2 + CIS playbooks>                  # installs the agent
terraform apply                                 # adds the virtio-serial channel
```

Rebuilding one node in a live cluster uses the per-node override instead —
`nodes["core-srv-1"].qemu_agent = false` — so the other two keep their agent.

Adding the channel requires a guest reboot, but `reboot_after_update = false`
means Terraform will not do it. Reboot each guest yourself, one at a time,
confirming etcd and Ceph health in between. All three nodes are the etcd quorum.

## Upgrading the base image

There is no in-place upgrade. `file_name` derives from the URL, so bumping
`ubuntu_image_url` and `ubuntu_image_checksum` changes the disk's `import_from`
and forces replacement — which `prevent_destroy` correctly refuses.

Upgrading is a deliberate node-by-node rebuild: drain the node, remove
`prevent_destroy` for that apply, replace, restore the guard, rejoin, verify
quorum, then move to the next.

## Recovering a stale state lock

State locking uses an S3 conditional-write lock object. An apply killed
mid-flight leaves it behind with no TTL, and every later plan then fails to
acquire it:

```bash
terraform force-unlock <LOCK_ID>        # ID is printed in the error
terraform plan -lock-timeout=5m         # wait rather than fail, when contended
```

Both need the backend reachable. State lives in RustFS behind an ingress on the
**rpi-rke2** cluster, so an outage there blocks all Terraform work on `core`.

## Known constraints

- **State is not encrypted at rest.** `encrypt = true` fails — RustFS needs
  `RUSTFS_SSE_S3_MASTER_KEY` configured server-side first.
- **One keypair spans two trust tiers.** The key the provider uses for
  hypervisor SSH also authorises the `ansible` user inside every guest. Rotating
  either rotates both; splitting them needs the Ansible side coordinated.
- **Single resolver and single API endpoint.** `nameservers` has one entry, and
  `proxmox_endpoint` names one hypervisor with no failover.
- **cloud-init changes do not reach running guests.** Editing `nameservers`,
  `gateway` or `ip_cidr` rewrites the seed drive but a provisioned guest will
  not re-apply it; state will report values the guest is not using.
- **`started = true`** means an unrelated apply powers a deliberately stopped
  node back on.
