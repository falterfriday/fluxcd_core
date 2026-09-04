# Core Cluster — Terraform

Provisions three `core-srv-*` guests on Proxmox that become the `core` RKE2
cluster. One guest per hypervisor, pinned.

Everything below is a prerequisite that lives **outside this repo**. None of it
is discoverable from the code, which is why it is written down here.

## Prerequisites

| What | Where | Notes |
|---|---|---|
| Proxmox API token | Generated from PVE | `export PROXMOX_VE_API_TOKEN="$(tr -d '\n' < ~/.proxmox)"` |
| RustFS state credentials | `~/.aws/credentials` (mode 600) | S3 backend |
| PVE cluster CA | `/usr/local/share/ca-certificates/pve-root-ca.crt` | Required — `proxmox_insecure = false` |
| age key for SOPS | Generated AGE key | `export SOPS_AGE_KEY_FILE=<PATH_TO_AGE_KEY_FILE>` |
| Terraform | >= 1.10.0 | `use_lockfile` in the S3 backend requires >1.10 |

### Trusting the PVE CA

The API presents a certificate from the cluster's own CA. Its SAN already covers
the endpoint IP, so only the CA needs installing:

```bash
ssh -t user@<pve-host> 'sudo cat /etc/pve/pve-root-ca.pem' > pve-root-ca.pem
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
SDN.Audit, SDN.Use
```

Three of these were discovered the hard way, each surfacing only when a new code
path ran:

- `VM.Audit` — without it Terraform cannot read the VMs, concludes they were
  deleted, and plans to recreate live guests.
- `Sys.Audit` — required for `query-url-metadata`, which the image download
  resource calls. Missing, plans emit a misleading "remote file doesn't exist"
  warning.
- `SDN.Use` — required to *modify* a NIC, though not to create one. Only
  surfaces the first time the firewall flag is flipped.

The token also currently holds `SDN.Allocate`, which this module does not need.

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

## Firewall

**The PVE firewall is enabled in this environment.** `var.firewall_enabled`
defaults to `false` in `variables.tf`, but that default is a safety fallback for
a fresh environment — it is not the state of this one. The live value comes from
`terraform.tfvars`. Check what is actually in effect:

```bash
echo 'var.firewall_enabled' | terraform console     # -> true
```

Guest input policy is `DROP`. Reachable from `firewall_admin_sources`: SSH 22,
Kubernetes API 6443, ICMP. Reachable only between the guests themselves
(`+core-nodes` ipset): etcd 2379-2381, RKE2 supervisor 9345, kubelet 10250,
kube-proxy 10256, Calico VXLAN 4789/udp, Typha 5473, Ceph 3300/6789/6800-7300.

Calico here runs VXLAN `Always` on port **4789**, not canal's 8472. Confirm with
`kubectl get ippools -o yaml` before changing encapsulation rules.

### Standing this up somewhere new

Order matters, and getting it wrong costs you access to the guests:

1. Set `firewall_admin_sources` and apply with `firewall_enabled = false`.
2. Confirm the security group carries admin rules for 22, 6443 and ICMP —
   without them the first node you enable drops SSH and kubectl.
3. Enable the cluster master switch.
4. Enable one node at a time with `-target` on both the VM and its
   `firewall_options`, verifying connectivity between each. Enable the node your
   kubeconfig points at **last**, so kubectl survives to verify the others.

Modifying a NIC needs `SDN.Use` on the bridge path — creating one does not, so
this only surfaces the first time the firewall flag is flipped.

## Generated files

Two files are written into `../ansible/` on apply, and are gitignored there:

```
ansible/inventory/core.ini                       # hosts and addresses
ansible/inventory/group_vars/core/generated.yml  # ansible_user, api hostname,
                                                 # ingress LB IP, OSD device
```

This makes Terraform the single source of truth for topology and keeps the
Ansible tree free of addresses. `terraform apply` must therefore run before any
Ansible run, even when no infrastructure has changed.

## Known constraints

- **Version history retention is unverified.** A lifecycle policy expiring
  noncurrent state versions is applied to the bucket, but RustFS accepting the
  config is not proof it runs the rule. A canary object with 8 versions was left
  in the bucket to check on 2026-09-11; if it has not trimmed to 6, purge old
  versions manually. `NewerNoncurrentVersions` is likely ignored entirely —
  RustFS rejects it without `NoncurrentDays`.
- **One keypair spans two trust tiers.** The key the provider uses for
  hypervisor SSH also authorises the designated user inside every guest. Rotating
  either rotates both; splitting them needs the Ansible side coordinated.
- **Single resolver and single API endpoint.** `nameservers` has one entry, and
  `proxmox_endpoint` names one hypervisor with no failover.
- **cloud-init changes do not reach running guests.** Editing `nameservers`,
  `gateway` or `ip_cidr` rewrites the seed drive but a provisioned guest will
  not re-apply it; state will report values the guest is not using.
- **`started = true`** means an unrelated apply powers a deliberately stopped
  node back on.
- **`ingress_sources` is empty.** Harmless while nothing uses ingress-nginx, but
  the moment an Ingress is created, hostPorts 80/443 are dropped until it is set.
- **The hypervisors are not filtered.** Datacenter `input_policy` is `ACCEPT`;
  only the guests enforce. Tightening it needs node-level management rules first
  or you lose 8006 and 22 on all three hosts.
