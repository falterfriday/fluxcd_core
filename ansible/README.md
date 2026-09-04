# core cluster — Ansible

Turns the three Terraform-provisioned guests into an RKE2 cluster, using the
`lablabs.rke2` role that already builds the internal, staging and production
clusters.

Run this after `terraform apply` and before anything Flux-related.

## Prerequisites

| What | Where | Notes |
|---|---|---|
| Ansible | not on `PATH` | lives in `~/venv/bin` |
| Roles and collections | `ansible-galaxy install -r requirements.yml` | both roles are version-pinned |
| Generated inventory | written by `terraform apply` | see below |
| RKE2 join token | `RKE2_TOKEN` in the environment | never committed |
| SSH access | key authorised for the guest login account | the same key Terraform uses |

Run playbooks **from this directory** so `ansible.cfg` is picked up. Without it
Ansible resolves `group_vars/` relative to the inventory it was given, not the
playbook, and silently loads nothing.

## Terraform generates two files

This directory contains no addresses, hostnames or account names. Terraform
owns them and writes them here on apply:

```
ansible/inventory/core.ini                       # hosts and ansible_host
ansible/inventory/group_vars/core/generated.yml  # ansible_user, api hostname,
                                                 # ingress LB IP, OSD device
```

Both are gitignored. Committed `.example` copies alongside them record the
shape and give CI something to validate. A fresh checkout has neither until
`terraform apply` has run.

Two more values are **derived** rather than generated, so they cannot drift
from the inventory:

```yaml
rke2_api_ip:          first host in the servers group
rke2_additional_sans: every host in the group, plus the API hostname
```

## Running it

```bash
export PATH="$HOME/venv/bin:$PATH"
export RKE2_TOKEN=$(openssl rand -hex 32)

ansible-galaxy install -r requirements.yml
ansible-playbook playbooks/core-cluster.yml
```

The kubeconfig is fetched to `/tmp/core.yaml` on the control node.

Hardening is a separate playbook — see CIS hardening below.

## What the playbook does

One play against all three guests, then a report:

1. Waits for SSH to settle after first boot.
2. Installs `qemu-guest-agent`, `nfs-common`, `open-iscsi`.
3. Asserts the guest agent unit is present. It is deliberately **not** started —
   the unit is static and device-activated, and refuses to start until
   `/dev/virtio-ports/org.qemu.guest_agent.0` exists. That device only appears
   after Terraform's second pass sets `agent = true` and the guest reboots.
4. Loads `rbd` and `nbd` for Rook-Ceph, persistently.
5. Asserts the OSD device is raw. Rook zaps it on first use, which is correct
   for a new disk and catastrophic for one holding data, so the play stops if
   anything has claimed it. The device is addressed by `/dev/disk/by-id/...`,
   never `/dev/sdb` — kernel names are not stable across reboots.
6. Disables swap, in memory and in `/etc/fstab`.
7. Runs `lablabs.rke2`.
8. Waits for every node to register and prints them.

## Ingress manifest

`files/rke2-ingress-nginx-config.yaml` is dropped into RKE2's manifests
directory so it applies as the cluster starts, before Flux exists. The role
applies custom manifests with `ansible.builtin.template`, so the file is
Jinja-rendered — the MetalLB address comes from `core_ingress_lb_ip`.

MetalLB is not installed at that point, so the Service stays `Pending` until
Flux reconciles it. That is the intended order, not a fault.

## CIS hardening

`playbooks/harden.yml` applies the ansible-lockdown UBUNTU24-CIS benchmark,
pinned to 1.5.0 in `requirements.yml`. It runs `serial: 1` — one node at a time,
because all three are the etcd quorum.

Run it **after** the cluster is up, not before:

```bash
ansible-playbook playbooks/harden.yml --limit core-srv-2
```

`skip_reboot` is `true`, so the role never reboots a node. Reboots are yours to
sequence, one at a time, checking etcd health in between.

### Rules disabled, and why

The overrides live in `inventory/group_vars/core/cis.yml`. Every one exists
because the default would break RKE2 or this cluster specifically:

| Rule | Why disabled |
|---|---|
| `1_3_1_1` – `1_3_1_4`, `config_aide` | AIDE, off by request |
| `1_1_1_6` | Blacklists `overlayfs`. The live module is `overlay` (alias `fs-overlay`) with no `overlayfs` alias, so this is probably a no-op — disabled anyway because the cost of being wrong is containerd failing to start, and the benefit here is nil |
| `3_3_1` | Sets `net.ipv4.ip_forward=0`. Kubernetes requires it to be `1`; this would break all pod networking |
| `4_1_1` – `4_4_3_4` (29 rules) | Manage ufw/nftables/iptables. kube-proxy and Calico own the host iptables chains, and a CIS default-deny policy would sever etcd and pod traffic. Filtering is done at the Proxmox layer instead |

### Audit daemon overrides

The role's auditd defaults halt the machine when the audit partition fills:

```yaml
ubtu24cis_auditd_disk_full_action: rotate          # role default: halt
ubtu24cis_auditd_admin_space_left_action: syslog   # role default: halt
ubtu24cis_auditd_max_log_file_action: rotate       # role default: keep_logs
```

With one 100 GB root shared by containerd images, logs and Ceph, `keep_logs`
plus `halt` is a path to losing a node — and since all three fill at the same
rate, plausibly all three at once.

### Left enabled deliberately

- **auditd** is installed and enabled. It is noisy on a Kubernetes node; watch
  log volume after the first node.
- **`Defaults use_pty` in sudoers** (5.2.x). This is safe because `ansible.cfg`
  does not enable pipelining. If you ever turn pipelining on, `become` breaks.
- **Partition rules** (1.1.2.x) audit for separate `/tmp`, `/var`, `/home`.
  This is a single-root image so they report and move on.
- **`squashfs` blacklist** — snapd is inactive with zero snaps installed.

## Linting

CI runs the same four checks; run them locally the same way:

```bash
yamllint .
ansible-lint playbooks/ inventory/
ansible-playbook --syntax-check playbooks/core-cluster.yml
ansible-playbook --syntax-check playbooks/harden.yml
ansible-inventory --list > /dev/null
```

`ansible-lint` is scoped to `playbooks/` and `inventory/` on purpose. Run bare,
it follows `roles_path` into `~/.ansible/roles` and grades the third-party
`lablabs.rke2` and `UBUNTU24-CIS` roles, which fail with dozens of violations
that are not ours.

`ansible-lint` passes at the `production` profile.

## Constraints

- **All three nodes are the etcd quorum.** There is no agent tier. Anything
  that restarts them together takes the cluster down.
- **The playbook assumes the firewall is already enforcing.** SSH reaches the
  guests only from the admin sources Terraform configured.
- **`rke2_token` is mandatory.** The lookup fails the run if `RKE2_TOKEN` is
  unset, which is deliberate — there is no default and no committed value.
- **Servers are schedulable.** With three nodes, tainting the control plane
  would leave nowhere for Ceph OSDs, which must sit on the node holding the
  disk. Resource requests and Rook's priority classes carry the isolation.
