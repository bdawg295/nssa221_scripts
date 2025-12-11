#!/bin/bash

# ==============================================================================
# RIT NSSA221 - Lab 4: RAID 1 & RAID 5 Setup Only
# Features: Persistent Mounts, Automatic Error Handling, Verbose Logging
# ==============================================================================

# 1. AUTOMATIC DEBUGGING & SAFETY
# ------------------------------------------------------------------------------
# Exit immediately if a command exits with a non-zero status
set -e 

# Trap errors and print the line number where it failed
error_handler() {
    echo "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    echo "ERROR: Script failed at line $1."
    echo "Please check the error message above for details."
    echo "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
trap 'error_handler $LINENO' ERR

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "CRITICAL: This script must be run as root."
  exit 1
fi

echo ">> Starting RAID Configuration Script..."
echo ">> Installing necessary tools (mdadm, gdisk)..."
dnf install -y mdadm gdisk > /dev/null

# ==============================================================================
# ACTIVITY 3: RAID 1 CONFIGURATION
# Devices: /dev/nvme0n3, /dev/nvme0n4
# Target: /dev/md0 (MBR Partition Table)
# ==============================================================================
echo "----------------------------------------------------------------"
echo ">> ACTIVITY 3: Setting up RAID 1 (/dev/md0)"
echo "----------------------------------------------------------------"

# Check if RAID already exists to prevent errors
if [ -e /dev/md0 ]; then
    echo "WARNING: /dev/md0 already exists. Stopping to prevent data loss."
    echo "If you are retrying, please wipe the drives first."
    exit 1
fi

echo ">> Creating RAID 1 array with 2 devices..."
# [cite: 282, 284]
yes | mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/nvme0n3 /dev/nvme0n4

echo ">> RAID 1 created. Waiting 5 seconds for sync to stabilize..."
sleep 5

echo ">> Partitioning /dev/md0 with MBR (Master Boot Record)..."
# [cite: 314, 318, 320, 323]
# fdisk interaction:
# n (new) -> p (primary) -> 1 -> default -> +1G (1GB size)
# n (new) -> e (extended) -> 2 -> default -> default (rest of disk)
# n (new) -> l (logical) -> default -> default (fills extended)
# w (write)
sed -e 's/\s*\([\+0-9a-zA-Z]*\).*/\1/' << EOF | fdisk /dev/md0
n
p
1

+1G
n
e
2


n
l


w
EOF

echo ">> Updating kernel partition table..."
partprobe /dev/md0
sleep 2

echo ">> Formatting partitions to XFS..."
# Note: Logical partitions in MBR usually start at 5 (p5) [cite: 334]
mkfs.xfs -f /dev/md0p1
mkfs.xfs -f /dev/md0p5

echo ">> Creating mount points /media/nfs1 and /media/nfs2..."
# [cite: 341]
mkdir -p /media/nfs1
mkdir -p /media/nfs2

echo ">> Mounting RAID 1 partitions..."
mount /dev/md0p1 /media/nfs1
mount /dev/md0p5 /media/nfs2

# ==============================================================================
# ACTIVITY 4: RAID 5 CONFIGURATION
# Devices: /dev/nvme0n5, /dev/nvme0n6, /dev/nvme0n7
# Target: /dev/md1 (GPT Partition Table)
# ==============================================================================
echo "----------------------------------------------------------------"
echo ">> ACTIVITY 4: Setting up RAID 5 (/dev/md1)"
echo "----------------------------------------------------------------"

if [ -e /dev/md1 ]; then
    echo "WARNING: /dev/md1 already exists. Stopping."
    exit 1
fi

echo ">> Creating RAID 5 array with 3 devices..."
# [cite: 366]
yes | mdadm --create /dev/md1 --level=5 --raid-devices=3 /dev/nvme0n5 /dev/nvme0n6 /dev/nvme0n7

echo ">> RAID 5 created. Waiting 5 seconds for sync..."
sleep 5

echo ">> Partitioning /dev/md1 with GPT (GUID Partition Table)..."
# [cite: 362, 390]
# gdisk interaction:
# n (new) -> 1 -> default -> +2G -> 8300 (Linux FS)
# n (new) -> 2 -> default -> +2G -> 8300
# n (new) -> 3 -> default -> +2G -> 8300
# w (write) -> Y (confirm)
gdisk /dev/md1 << EOF
n
1

+2G
8300
n
2

+2G
8300
n
3

+2G
8300
w
Y
EOF

echo ">> Updating kernel partition table..."
partprobe /dev/md1
sleep 2

echo ">> Formatting RAID 5 partitions to XFS..."
# [cite: 394]
mkfs.xfs -f /dev/md1p1
mkfs.xfs -f /dev/md1p2
mkfs.xfs -f /dev/md1p3

echo ">> Creating mount points /media/samba1, samba2, samba3..."
# [cite: 417]
mkdir -p /media/samba1
mkdir -p /media/samba2
mkdir -p /media/samba3

echo ">> Mounting RAID 5 partitions..."
mount /dev/md1p1 /media/samba1
mount /dev/md1p2 /media/samba2
mount /dev/md1p3 /media/samba3

# ==============================================================================
# ACTIVITY 5: PERSISTENCE (FSTAB)
# ==============================================================================
echo "----------------------------------------------------------------"
echo ">> ACTIVITY 5: Configuring Persistence (/etc/fstab)"
echo "----------------------------------------------------------------"

# Backup fstab first
cp /etc/fstab /etc/fstab.bak
echo ">> Backup of fstab saved to /etc/fstab.bak"

# Helper function to get UUIDs
get_uuid() {
  blkid -s UUID -o value $1
}

echo ">> Fetching UUIDs..."
UUID_R1_P1=$(get_uuid /dev/md0p1)
UUID_R1_P5=$(get_uuid /dev/md0p5)
UUID_R5_P1=$(get_uuid /dev/md1p1)
UUID_R5_P2=$(get_uuid /dev/md1p2)
UUID_R5_P3=$(get_uuid /dev/md1p3)

echo ">> Appending entries to /etc/fstab..."
# [cite: 503]

# RAID 1 Entries
echo "UUID=$UUID_R1_P1 /media/nfs1 xfs defaults 0 0" >> /etc/fstab
echo "UUID=$UUID_R1_P5 /media/nfs2 xfs defaults 0 0" >> /etc/fstab

# RAID 5 Entries
echo "UUID=$UUID_R5_P1 /media/samba1 xfs defaults 0 0" >> /etc/fstab
echo "UUID=$UUID_R5_P2 /media/samba2 xfs defaults 0 0" >> /etc/fstab
echo "UUID=$UUID_R5_P3 /media/samba3 xfs defaults 0 0" >> /etc/fstab

echo "----------------------------------------------------------------"
echo ">> SUCCESS: RAID setup and persistence configuration complete."
echo ">> Verifying mounts..."
df -h | grep media
echo "----------------------------------------------------------------"