# Homeserver disk layout and reproducible install

This documents the physical disk layout of the honeypot homeserver
(`supermicro`) as it actually exists today, and a generated Ubuntu
**autoinstall** config (the Ubuntu/subiquity equivalent of Windows'
`autounattend.xml`) that reproduces the layout the box had at the time of
the #518 smoke-test research.

> **The autoinstall config below no longer describes this host.** The
> physical table and the provisioning steps were re-measured read-only on
> 2026-09-27. `supermicro` has since been reinstalled as **Rocky Linux
> 10.2** and no longer runs the Ubuntu/`curtin` layout: it uses LVM (the
> original notes recorded "no LVM"), `/var` sits on a *partition* of the
> RAID LUN rather than the whole disk, and swap is a 32G LVM logical
> volume rather than a swapfile. The original capture was 2026-08-04, when
> the fstab comments did literally say "was on /dev/sdX during curtin
> installation" — that evidence was sound for the Ubuntu install, which
> has since been replaced. Keep the autoinstall file as the record of the
> Ubuntu layout; do not use it as a rebuild target for the current host.
> See `docs/HOST-TUNING.md` for the tuning that *does* apply to the Rocky
> install.

## Why this layout, not one big disk

The OS disk (NVMe) is deliberately small and separate from the bulk
storage disks. Docker/Arcane state, container images, and honeypot capture
data are heavy-churn and can grow unpredictably (payload captures, ELK
indices, sandbox images) — keeping them off the boot disk means a runaway
log or a bad `docker system df` can't take the OS down with it, and a
reinstall of the OS disk alone doesn't touch captured evidence.

## Physical layout (as installed)

Re-measured read-only on 2026-09-27 via `lsblk`/`lvs`/`findmnt`/`df`.

| Device | Model | Size | Partition table | Filesystem | Mount | Role |
|---|---|---|---|---|---|---|
| `nvme0n1` | PC401 NVMe SK hynix 1TB | 953.9G | GPT, 3 partitions | vfat (p1, 600M) / xfs (p2, 2G) / LVM2_member (p3, 951.3G) | `/boot/efi`, `/boot`, — | OS boot disk |
| └ `rl-root` | (LVM on `nvme0n1p3`) | 70G | — | xfs | `/` | OS root |
| └ `rl-swap` | (LVM on `nvme0n1p3`) | 32G | — | swap | `[SWAP]` | Swap |
| └ `rl-home` | (LVM on `nvme0n1p3`) | 849.3G | — | xfs | `/home` | Home |
| `sdb` | AVAGO MR9440-8i (RAID LUN) | 8.7T | GPT, 1 partition (`sdb1`, whole remaining size) | xfs | `/var` | Docker root, Arcane-managed stacks, container state (`/var/lib/docker`, `/var/dockge`) — now also `benchmarks/`, `training/`, `hf-cache/`, `buildx-cache/`, `ci-registry-mirror/`, the former `/mnt-1` workload |
| `sda` | PSSD T7 (**USB-attached**) | 465.8G | GPT, 1 partition (`sda1`) | ext4 | `/mnt/usb-recovery` | USB recovery disk, not local bulk storage |

Three of the four rows changed since the 2026-08-04 capture, and none of
the change is cosmetic. The OS disk is a different, 4x-larger NVMe; the
former `sda` bulk-storage disk (`/mnt-2`) is now a USB-attached portable
SSD mounted at `/mnt/usb-recovery`; and the boot disk is now LVM-backed
with a separate `/home`. The old `sr0` ATAPI optical drive is no longer
enumerated at all.

**`/mnt-1` and `/mnt-2` are both decommissioned.** `/mnt-1`'s RAID VD
(formerly `sdc`) suffered a two-drive fault on 2026-09-09 (#3158) and no
longer enumerates as a block device at all; the mount was unwired (#3159,
PR #3159) and everything that lived under it moved to `/var`. `/mnt-1`
itself survives on the host only as a directory of compatibility
symlinks into `/var` (`benchmarks`, `training`, `hf-cache`,
`buildx-cache`, `ci-registry-mirror`) so any script still hard-coding the
old path keeps resolving — new code should target `/var/*` directly. See
#3158/#3159 for the incident and decommission detail. `/mnt-2` is gone for
a different reason: its disk is the USB `PSSD T7` above, remounted at
`/mnt/usb-recovery`, so it is no longer local bulk storage and must not be
relied on for a rebuild.

`sdb` sits behind an AVAGO/LSI MR9440-8i hardware RAID controller and
appears to the OS as a SCSI LUN, not a raw disk — the controller's own
RAID/cache configuration (level, write policy, battery/flash backup) is out
of band from this OS-level view and needs to be captured separately from
the controller's own tooling (`storcli`/`perccli` or vendor equivalent) if
the RAID config itself needs to be reproducible, not just the OS
partitioning on top of it.

`/var` on its own disk is the key decision, and it has only become more
load-bearing: `/var/lib/docker` is **2.9T** and `/var/dockge` (stack data
for the 45 directories under `/var/dockge/stacks/`, including
Elasticsearch indices, Cowrie logs, payload captures, sandbox disks) is
**350G**. `/var` is 70% full (6.1T of 8.8T) with 2.7T free. The manifest
still declares 39 sync entries, 33 of which name one of the 34 directories
under `arcane/home/`; `rex86-eval` is present on disk but **not** in the
manifest (the other 6 manifest entries are root-level stacks). Putting `/var` on the RAID LUN instead of growing the root
filesystem remains the right call and should be preserved on any rebuild.

Swap is a **32G LVM logical volume** (`rl-swap`) in the `rl` volume group,
not a dedicated partition and not a swapfile — the 8G `/swap.img`
swapfile described in the 2026-08-04 capture no longer exists. 92G of RAM
means swap is a safety margin rather than a working set, though it was
under real pressure at measurement time (14.6G in use, priority -2).

`/var` also carries the two CI-created directories, both of which the
workflows cannot create for themselves (`/var` is `root:root 0755`, so a
`mkdir` as `github-ci-runner` gets `EACCES`) and both of which
`scripts/install-homeserver.sh` therefore provisions and then proves writable
per runner user:

| directory | holds | bounded by |
|---|---|---|
| `/var/buildx-cache/<runner>/<image>` | that runner's image-specific `type=local` buildx layer cache (#2822, #3605) | `scripts/prune-buildx-cache.sh`, 2 GiB per runner/image |
| `/var/image-sbom/<image>` | the digest-keyed CycloneDX SBOMs for the two dashboard images (#3321) | `scripts/prune-image-sbom.sh`, 10 records per image |

Neither is in the `/mnt-1` compatibility symlink list above: both were added
after the move, so no script hard-codes the old path. See
[CI-CD.md](CI-CD.md) for what writes them and why.

## Reproducing it: `autoinstall/homeserver-user-data.yaml`

The autoinstall config in
[`docs/autoinstall/homeserver-user-data.yaml`](autoinstall/homeserver-user-data.yaml)
automates identity, SSH, network, and package setup, but **storage is
intentionally left manual** — `interactive-sections: [storage]` makes
subiquity stop and show its normal guided/manual partitioning screen
instead of applying a `curtin` storage config. This isn't an oversight:
`match:` filtering by size, serial, and wwn was each tried and either
ambiguous (two identically-sized RAID LUNs) or actively wrong (wwn
matching, even with values confirmed correct by a fresh probe, twice
picked the USB installer stick instead of the target disk). `match:`
does not reliably work for this hardware in this installer version, so
manual partitioning at install time is the only approach proven not to
put data on the wrong disk. Boot an Ubuntu Server 24.04+ ISO with
`autoinstall` on the kernel command line (or bake it into a custom ISO)
pointing at this file, e.g. served over HTTP:

```
# on the install media's GRUB/boot prompt:
autoinstall ds=nocloud-net;s=http://<your-http-server>/autoinstall/
```

with `homeserver-user-data.yaml` renamed to `user-data` alongside an empty
`meta-data` file at that URL path, per Ubuntu's
[autoinstall quick-start](https://canonical-subiquity.readthedocs-hosted.com/en/latest/tutorial/providing-autoinstall.html).

**What the template automates:**
- Static hostname `supermicro`, `Europe/Berlin` timezone, matching the
  live box — **change both** for a second/different build server; don't
  copy this file byte-for-byte onto new hardware without editing the
  identity fields marked `# CHANGE ME` in the template.
- Network config is deliberately left as DHCP-on-all-NICs in the
  template, not copied from the live box's netplan (which pins interfaces
  by MAC address and sets up a metric-based dual-uplink — that's specific
  to this box's NICs and the WireGuard-uplink setup documented in
  `docs/CGNAT-DEPLOYMENT.md`, and shouldn't be blindly reproduced on
  different hardware).
- SSH (key-only, no password auth) and the `xfsprogs`/`nvme-cli` packages
  the manual partitioning step below needs.

**What has to be done by hand, at the storage screen.** For reproducing
the **former Ubuntu layout** (the one this template was written against,
and the one the 2026-08-04 capture recorded): 3-disk layout (NVMe boot/OS:
GPT, EFI + ext4 root; `/var`: whole-disk xfs, no partition table; `/mnt-2`:
GPT + single xfs partition), no LVM, 8G swapfile instead of a swap
partition. That is **not** the live layout any more — the box now uses LVM
with a separate `/home`, `/var` on a partition, and a 32G swap LV, and its
disks have all been replaced (see the table above). Do not use this
paragraph as a partition plan for the current host; it is a record of what
the autoinstall flow produced. `/mnt-1` is no longer part of the target layout (decommissioned,
see above) — do not recreate it on a rebuild. The template does **not**
attempt to reproduce the AVAGO RAID controller's own LUN configuration
either — that has to happen before the OS installer ever sees a block
device, via the controller's own boot-time utility or `storcli`, and if the
MegaRAID LUN (`/var`) refuses to wipe/format even manually, its VD
likely needs deleting and recreating at the controller's own config
utility first. Document the RAID config separately if/when a bare-metal
rebuild is actually planned (out of scope for this pass — see open
question in
[`docs/research/518-smoke-test-research.md`](research/518-smoke-test-research.md)).

**What's intentionally not templated:** GPU driver install, Docker/
Arcane install, NVIDIA container toolkit, WireGuard, and all the honeypot
stack deployment — those are post-install configuration management, not
disk partitioning, and belong in the single install script that #518 is
building, not in the autoinstall `user-data`. Ubuntu autoinstall supports
a `late-commands`/`user-data` cloud-init hook to chain into a
provisioning script automatically after first boot; once the install
script from #518 exists, wire it in there rather than growing this
YAML file into a general-purpose provisioner.

## VPS: no equivalent template

The VPS (`YOUR.VPS.IP.HERE`, matching vps/.env.example's SURICATA_HOME_NET convention) is a single 120G virtio disk (`vda`), plain GPT
with root/boot/ESP partitions, no RAID, no extra mounts — it was
provisioned from the hosting provider's stock image, not PXE/ISO
autoinstall, so there's no autoinstall config to generate for it. If the
provider supports cloud-init user-data at instance-creation time, that's
the equivalent mechanism worth documenting once someone confirms which
provider workflow was actually used to create this instance — not
guessed at here.
