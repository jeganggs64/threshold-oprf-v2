#!/usr/bin/env bash
#
# Build a sealed TOPRF node disk image for Azure Confidential VMs.
#
# Produces a fixed-size VHD containing:
# - Signed boot chain: shim (Microsoft-signed) → GRUB (Canonical-signed) → kernel (signed)
# - Linux kernel with Hyper-V, SEV-SNP, vTPM, kernel DHCP
# - Initramfs with ONLY the toprf-node binary + BusyBox init + CA certs
# - NO OS, NO SSH, NO shell after boot, NO package manager
#
# Secure Boot ensures the vTPM PCR measurements are trustworthy:
#   PCR 4 = shim + GRUB hash
#   PCR 9 = kernel + initrd hash
# Combined with SEV-SNP attestation, this proves exactly what code is running.
#
# Must run as root on Ubuntu. Designed for CI (GitHub Actions ubuntu-latest).
#
# Usage:
#   sudo ./build-image.sh --binary /path/to/toprf-node --output disk.vhd
#
set -euo pipefail

BINARY=""
OUTPUT="disk.vhd"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)  BINARY="$2"; shift 2 ;;
        --output)  OUTPUT="$2"; shift 2 ;;
        *) echo "Usage: $0 --binary <path> [--output <path>]"; exit 1 ;;
    esac
done

if [[ -z "$BINARY" ]]; then echo "Error: --binary required"; exit 1; fi
if [[ ! -f "$BINARY" ]]; then echo "Error: binary not found: $BINARY"; exit 1; fi
if [[ $EUID -ne 0 ]]; then echo "Error: must run as root"; exit 1; fi

WORKDIR=$(mktemp -d)
RAW="$WORKDIR/disk.raw"

cleanup() {
    umount -R "$WORKDIR/mnt" 2>/dev/null || true
    losetup -D 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "=== Building sealed TOPRF node image ==="
echo ""

# ---- 1. Download signed boot components ----
echo "[1/7] Downloading signed boot components..."
apt-get update -qq

# Download packages (don't install to host — just extract)
PKG_DIR="$WORKDIR/packages"
mkdir -p "$PKG_DIR"
cd "$PKG_DIR"

# Resolve the actual kernel package (linux-image-azure is a meta-package)
KERNEL_PKG=$(apt-cache depends linux-image-azure 2>/dev/null | grep "Depends: linux-image-" | grep -v "linux-image-azure" | awk '{print $2}' | head -1)
if [[ -z "$KERNEL_PKG" ]]; then
    # Fallback: use the generic kernel
    KERNEL_PKG=$(apt-cache depends linux-image-generic 2>/dev/null | grep "Depends: linux-image-" | grep -v "linux-image-generic" | awk '{print $2}' | head -1)
fi
echo "  Kernel package: $KERNEL_PKG"

# Download the signed boot chain + resolved kernel
apt-get download \
    shim-signed \
    grub-efi-amd64-signed \
    "$KERNEL_PKG" \
    busybox-static \
    ca-certificates 2>/dev/null

# Extract all packages
EXTRACT="$WORKDIR/extract"
mkdir -p "$EXTRACT"
for deb in "$PKG_DIR"/*.deb; do
    dpkg-deb -x "$deb" "$EXTRACT"
done

# Find the key files
SHIMX64=$(find "$EXTRACT" -name "shimx64.efi.signed*" -o -name "shimx64.efi" | head -1)
GRUBX64=$(find "$EXTRACT" -name "grubx64.efi.signed" -o -name "grubnetx64.efi.signed" | head -1)
# Fallback: look for grub in the standard signed location
if [[ -z "$GRUBX64" ]]; then
    GRUBX64=$(find "$EXTRACT" -path "*/grub-efi-amd64-signed/*grubx64*" | head -1)
fi
VMLINUZ=$(find "$EXTRACT/boot" -name "vmlinuz-*" | head -1)
MODULES_DIR=$(find "$EXTRACT/lib/modules" -maxdepth 1 -mindepth 1 -type d | head -1)
BUSYBOX=$(find "$EXTRACT" -name "busybox" -path "*/bin/*" | head -1)
CA_CERTS="$EXTRACT/etc/ssl/certs"

echo "  shim:    $SHIMX64"
echo "  grub:    $GRUBX64"
echo "  kernel:  $VMLINUZ"
echo "  modules: $MODULES_DIR"
echo "  busybox: $BUSYBOX"

for f in "$SHIMX64" "$VMLINUZ" "$BUSYBOX"; do
    if [[ -z "$f" || ! -f "$f" ]]; then
        echo "Error: missing boot component"
        exit 1
    fi
done

# ---- 2. Build initramfs ----
echo "[2/7] Building initramfs..."
INITRAMFS_DIR="$WORKDIR/initramfs"
mkdir -p "$INITRAMFS_DIR"/{dev,proc,sys,tmp,bin,sbin,etc/ssl/certs,usr/local/bin,var/lib/toprf,lib/modules}

# Init script — runs at boot, then exec's into the TOPRF binary
cat > "$INITRAMFS_DIR/init" <<'INITEOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /var/lib/toprf

# Load Hyper-V and TEE modules
for mod in hv_vmbus hv_storvsc hv_netvsc hv_utils tpm_crb sev-guest; do
    modprobe $mod 2>/dev/null
done

# Wait for network (kernel ip=dhcp handles DHCP)
i=0; while [ $i -lt 30 ]; do
    ip addr show eth0 2>/dev/null | grep -q "inet " && break
    i=$((i+1)); sleep 1
done

echo "=== TOPRF Node starting ==="
ip addr show eth0 2>/dev/null | grep "inet "
exec /usr/local/bin/toprf-node --join --port 3001 --data-dir /var/lib/toprf
INITEOF
chmod +x "$INITRAMFS_DIR/init"

# Binary
cp "$BINARY" "$INITRAMFS_DIR/usr/local/bin/toprf-node"
chmod +x "$INITRAMFS_DIR/usr/local/bin/toprf-node"

# BusyBox (for init script: sh, mount, modprobe, ip, sleep, grep, echo)
cp "$BUSYBOX" "$INITRAMFS_DIR/bin/busybox"
chmod +x "$INITRAMFS_DIR/bin/busybox"
for cmd in sh mount umount modprobe ip sleep echo cat grep; do
    ln -sf busybox "$INITRAMFS_DIR/bin/$cmd"
done
ln -sf ../bin/busybox "$INITRAMFS_DIR/sbin/modprobe"

# CA certs
if [[ -d "$CA_CERTS" ]]; then
    cp -a "$CA_CERTS"/* "$INITRAMFS_DIR/etc/ssl/certs/" 2>/dev/null || true
fi

# Kernel modules (only the ones we need)
if [[ -n "$MODULES_DIR" ]]; then
    KVER=$(basename "$MODULES_DIR")
    mkdir -p "$INITRAMFS_DIR/lib/modules/$KVER/kernel"
    for mod in hv_vmbus hv_storvsc hv_netvsc hv_utils tpm_crb sev-guest ccp; do
        find "$MODULES_DIR" -name "${mod}*" -exec cp --parents {} "$INITRAMFS_DIR/" \; 2>/dev/null || true
    done
    depmod -b "$INITRAMFS_DIR" "$KVER" 2>/dev/null || true
fi

# Pack initramfs
(cd "$INITRAMFS_DIR" && find . | cpio -o -H newc 2>/dev/null | gzip) > "$WORKDIR/initramfs.img"
echo "  Initramfs: $(( $(stat -c%s "$WORKDIR/initramfs.img") / 1024 / 1024 )) MB"

# ---- 3. Create disk image ----
echo "[3/7] Creating disk image (256MB)..."
dd if=/dev/zero of="$RAW" bs=1M count=256 status=none
sgdisk -o "$RAW"
sgdisk -n 1:2048:0 -t 1:EF00 -c 1:"ESP" "$RAW"

# ---- 4. Install boot files ----
echo "[4/7] Installing boot files..."
LOOP=$(losetup --show -fP "$RAW")
mkfs.vfat -F32 "${LOOP}p1"

mkdir -p "$WORKDIR/mnt"
mount "${LOOP}p1" "$WORKDIR/mnt"

# Secure Boot chain: shim → grub → kernel
# EFI/BOOT/BOOTX64.EFI = shim (Microsoft-signed, first thing UEFI loads)
# EFI/BOOT/grubx64.efi = GRUB (Canonical-signed, loaded by shim)
mkdir -p "$WORKDIR/mnt/EFI/BOOT"
cp "$SHIMX64" "$WORKDIR/mnt/EFI/BOOT/BOOTX64.EFI"
if [[ -n "$GRUBX64" && -f "$GRUBX64" ]]; then
    cp "$GRUBX64" "$WORKDIR/mnt/EFI/BOOT/grubx64.efi"
fi

# Kernel + initramfs
mkdir -p "$WORKDIR/mnt/boot/grub"
cp "$VMLINUZ" "$WORKDIR/mnt/boot/vmlinuz"
cp "$WORKDIR/initramfs.img" "$WORKDIR/mnt/boot/initramfs.img"

# GRUB config
cat > "$WORKDIR/mnt/boot/grub/grub.cfg" <<'GRUBEOF'
set timeout=0
set default=0

menuentry "TOPRF Node" {
    linux /boot/vmlinuz console=ttyS0,115200n8 ip=dhcp
    initrd /boot/initramfs.img
}
GRUBEOF

umount "$WORKDIR/mnt"
losetup -d "$LOOP"

# ---- 5. Convert to VHD ----
echo "[5/7] Converting to VHD..."
RAW_SIZE=$(stat -c%s "$RAW")
MB=$((1024 * 1024))
ALIGNED_SIZE=$(( (RAW_SIZE + MB - 1) / MB * MB ))
if [[ $RAW_SIZE -ne $ALIGNED_SIZE ]]; then
    qemu-img resize -f raw "$RAW" "$ALIGNED_SIZE" 2>/dev/null
fi
qemu-img convert -f raw -o subformat=fixed,force_size -O vpc "$RAW" "$OUTPUT"

# ---- 6. Compute hashes ----
echo "[6/7] Computing hashes..."
IMAGE_HASH=$(sha256sum "$OUTPUT" | cut -d' ' -f1)
BINARY_HASH=$(sha256sum "$BINARY" | cut -d' ' -f1)
KERNEL_HASH=$(sha256sum "$VMLINUZ" | cut -d' ' -f1)
INITRAMFS_HASH=$(sha256sum "$WORKDIR/initramfs.img" | cut -d' ' -f1)

# ---- 7. Summary ----
VHD_SIZE=$(stat -c%s "$OUTPUT")
echo ""
echo "[7/7] Done."
echo ""
echo "=========================================="
echo "  Sealed TOPRF Node Image"
echo "=========================================="
echo "  Output:          $OUTPUT"
echo "  VHD size:        $(( VHD_SIZE / 1024 / 1024 )) MB"
echo ""
echo "  Hashes (SHA-256):"
echo "    Image:         $IMAGE_HASH"
echo "    Binary:        $BINARY_HASH"
echo "    Kernel:        $KERNEL_HASH"
echo "    Initramfs:     $INITRAMFS_HASH"
echo ""
echo "  Boot chain (Secure Boot):"
echo "    UEFI → shim (Microsoft-signed)"
echo "         → GRUB (Canonical-signed)"
echo "         → vmlinuz (Canonical-signed)"
echo "         → initramfs (toprf-node + busybox init)"
echo ""
echo "  After boot:"
echo "    PID 1 = toprf-node (busybox init exec'd away)"
echo "    No SSH. No shell. No OS."
echo ""
echo "  vTPM PCR measurements will cover:"
echo "    PCR 4 = shim + GRUB"
echo "    PCR 9 = kernel + initramfs"
echo "=========================================="
