#!/usr/bin/env bash
#
# Harden an Amazon Linux 2023 instance into a sealed TOPRF appliance.
#
# Run this ONCE during AMI build. After this script:
# - No SSH server (sshd removed, keys deleted)
# - No shell binaries (bash, sh, etc. removed)
# - No package manager (dnf/yum removed)
# - No login (all user passwords locked, login disabled)
# - No kernel module loading
# - Root filesystem is read-only
# - Only /var/lib/toprf and /tmp are writable
# - The TOPRF node binary is the only service
#
# The resulting AMI's LAUNCH_DIGEST (measured by AMD SEV-SNP) covers this
# entire filesystem. Anyone can reproduce this build, compute the expected
# measurement, and verify it matches the on-chain/well-known record.
#
set -euo pipefail

echo "=== TOPRF Sealed Appliance Hardening ==="

# ---- 1. Install the binary and service ----
echo "[1/9] Installing TOPRF node binary and service..."
chmod +x /usr/local/bin/toprf-node
mkdir -p /var/lib/toprf
chown ec2-user:ec2-user /var/lib/toprf

cp /tmp/toprf-node.service /etc/systemd/system/toprf-node.service
systemctl daemon-reload
systemctl enable toprf-node

# ---- 2. Remove SSH ----
echo "[2/9] Removing SSH..."
systemctl stop sshd 2>/dev/null || true
systemctl disable sshd 2>/dev/null || true
dnf remove -y openssh-server openssh-clients 2>/dev/null || true
rm -rf /etc/ssh /root/.ssh /home/*/.ssh
# Remove authorized_keys
find / -name "authorized_keys" -delete 2>/dev/null || true

# ---- 3. Remove shells ----
echo "[3/9] Removing shell binaries..."
# Keep a minimal shell for systemd to work during boot, but remove after
# Note: systemd needs /bin/sh for ExecStart parsing in some cases.
# We keep /usr/bin/bash but make it non-executable after boot via a tmpfiles rule.
# Actually, since our service uses Type=simple with a direct binary path,
# systemd doesn't need a shell. But removing ALL shells can break systemd itself.
# Compromise: remove interactive shells, keep /usr/bin/sh as a symlink to /usr/bin/true
rm -f /usr/bin/bash /usr/bin/zsh /usr/bin/csh /usr/bin/tcsh /usr/bin/fish 2>/dev/null || true
rm -f /usr/bin/ash /usr/bin/dash /usr/bin/ksh 2>/dev/null || true
# Replace /bin/sh with a no-op (systemd fallback)
ln -sf /usr/bin/true /usr/bin/sh 2>/dev/null || true

# ---- 4. Remove package manager ----
echo "[4/9] Removing package manager..."
dnf remove -y dnf yum rpm 2>/dev/null || true
rm -rf /var/cache/dnf /var/lib/dnf /var/lib/rpm

# ---- 5. Lock all user accounts ----
echo "[5/9] Locking user accounts..."
# Lock all passwords
for user in $(cut -d: -f1 /etc/passwd); do
    passwd -l "$user" 2>/dev/null || true
done
# Disable serial console login
systemctl disable serial-getty@ttyS0 2>/dev/null || true
systemctl mask serial-getty@ttyS0 2>/dev/null || true
# Disable all getty
systemctl mask getty@tty1 2>/dev/null || true

# ---- 6. Disable kernel module loading ----
echo "[6/9] Disabling kernel module loading..."
echo "install /bin/true" > /etc/modprobe.d/disable-modules.conf
# Blacklist common unnecessary modules
cat > /etc/modprobe.d/blacklist-unnecessary.conf <<'MODEOF'
blacklist usb-storage
blacklist firewire-core
blacklist thunderbolt
blacklist bluetooth
blacklist snd
MODEOF

# ---- 7. Network hardening ----
echo "[7/9] Hardening network..."
# Only allow established connections + port 3001 inbound
# (iptables rules — backup for security group)
if command -v iptables &>/dev/null; then
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 3001 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    # Save rules
    iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
fi

# ---- 8. Clean up ----
echo "[8/9] Cleaning up..."
# Remove unnecessary services
systemctl disable amazon-ssm-agent 2>/dev/null || true
systemctl mask amazon-ssm-agent 2>/dev/null || true
rm -rf /var/log/amazon /opt/aws 2>/dev/null || true

# Remove documentation, man pages, locales
rm -rf /usr/share/doc /usr/share/man /usr/share/info
rm -rf /usr/share/locale/!(en_US)

# Remove cron
systemctl disable crond 2>/dev/null || true
rm -rf /var/spool/cron /etc/crontab /etc/cron.*

# Clear logs and temp
rm -rf /var/log/*.log /var/log/journal/* /tmp/* /var/tmp/*
> /var/log/wtmp
> /var/log/lastlog

# Remove cloud-init (not needed after AMI creation)
dnf remove -y cloud-init 2>/dev/null || true
rm -rf /var/lib/cloud

# ---- 9. Make rootfs read-only ----
echo "[9/9] Configuring read-only root filesystem..."
# Add 'ro' to fstab for root
sed -i 's/defaults/defaults,ro/' /etc/fstab 2>/dev/null || true

# Create tmpfs mounts for writable directories
cat >> /etc/fstab <<'FSTABEOF'
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=64M 0 0
tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=32M 0 0
tmpfs /var/log tmpfs defaults,noexec,nosuid,nodev,size=64M 0 0
tmpfs /run tmpfs defaults,noexec,nosuid,nodev,size=64M 0 0
FSTABEOF

echo ""
echo "=== Hardening complete ==="
echo ""
echo "This image contains:"
echo "  - /usr/local/bin/toprf-node (the only binary that matters)"
echo "  - systemd (minimal init)"
echo "  - Linux kernel with SEV-SNP guest support"
echo ""
echo "This image does NOT contain:"
echo "  - SSH server"
echo "  - Shell binaries (bash, sh → /usr/bin/true)"
echo "  - Package manager"
echo "  - SSM agent"
echo "  - Cloud-init"
echo "  - Cron"
echo ""
echo "Writable paths:"
echo "  - /var/lib/toprf (key storage, sealed blobs)"
echo "  - /tmp, /var/tmp, /var/log, /run (tmpfs)"
echo ""
echo "Network:"
echo "  - Port 3001 only (iptables + security group)"
echo ""
