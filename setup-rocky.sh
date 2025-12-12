#!/bin/bash

# ==============================================================================
# RIT NSSA221 - Robust Unified Server Setup Script (v3.0)
# Target System: Rocky Linux 8
#
# INCLUDES:
# 1. AUTOMATIC: VS Code + Python Setup
# 2. MENU: RAID Configuration (Lab 04)
# 3. MENU: Apache Virtual Web Server (Lab 06)
# 4. MENU: Rsync Daemon Configuration (Lab 05)
# 5. MENU: Samba File Sharing (Lab 05)
# ==============================================================================

# --- Helper Functions ---

log() {
    echo -e "\e[32m[INFO]\e[0m $1"
}

warn() {
    echo -e "\e[33m[WARN]\e[0m $1"
}

error_exit() {
    echo -e "\e[31m[ERROR]\e[0m $1"
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error_exit "This script must be run as root (sudo)."
    fi
}

check_command() {
    if [ $? -ne 0 ]; then
        error_exit "Last command failed. Exiting to prevent system damage."
    fi
}

# ==============================================================================
# MODULE 0: VS CODE & DEV ENVIRONMENT (AUTOMATIC)
# ==============================================================================
setup_vscode_env() {
    echo "----------------------------------------------------------------"
    log "STARTING AUTOMATIC SETUP: VS Code & Python Environment"
    echo "----------------------------------------------------------------"

    # 1. Install Python 3
    log "Ensuring Python 3 is installed..."
    dnf install -y python3 python3-pip > /dev/null
    check_command

    # 2. Add VS Code Repository
    if [ ! -f /etc/yum.repos.d/vscode.repo ]; then
        log "Adding Microsoft VS Code repository..."
        rpm --import https://packages.microsoft.com/keys/microsoft.asc
        sh -c 'echo -e "[code]\nname=Visual Studio Code\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/vscode.repo'
        check_command
    else
        log "VS Code repository already exists."
    fi

    # 3. Install VS Code
    log "Installing Visual Studio Code..."
    dnf check-update > /dev/null 2>&1 || true 
    dnf install -y code > /dev/null
    check_command

    # 4. Install Extensions (Python Only)
    REAL_USER=$SUDO_USER
    
    if [ -z "$REAL_USER" ]; then
        warn "Script run as pure root (not sudo). Extensions will only be installed for root."
        TARGET_USER="root"
    else
        log "Detected actual user: $REAL_USER. Installing extensions for them..."
        TARGET_USER="$REAL_USER"
    fi

    install_ext() {
        EXTENSION=$1
        if [ "$TARGET_USER" == "root" ]; then
            code --install-extension $EXTENSION --force --no-sandbox --user-data-dir /root/.vscode-root
        else
            sudo -u $TARGET_USER code --install-extension $EXTENSION --force
        fi
    }

    log "Installing Python Extension for $TARGET_USER..."
    install_ext "ms-python.python"

    echo "----------------------------------------------------------------"
    log "VS CODE SETUP COMPLETE." 
    echo "----------------------------------------------------------------"
    sleep 2
}

# ==============================================================================
# MODULE 1: RAID CONFIGURATION (Lab 04)
# ==============================================================================
setup_raid() {
    echo "----------------------------------------------------------------"
    log "STARTING MODULE: RAID CONFIGURATION (Lab 04)"
    echo "----------------------------------------------------------------"

    if [ ! -e /dev/nvme0n3 ] || [ ! -e /dev/nvme0n4 ]; then
        error_exit "Required drives for RAID 1 (/dev/nvme0n3, /dev/nvme0n4) not found!"
    fi

    log "Installing RAID tools..."
    dnf install -y mdadm gdisk lvm2 > /dev/null
    check_command

    # --- RAID 1 Setup ---
    if [ -e /dev/md0 ]; then
        warn "RAID 1 (/dev/md0) already exists. Skipping creation."
    else
        log "Creating RAID 1 (/dev/md0)..."
        yes | mdadm --create /dev/md0 --level=1 --raid-devices=2 /dev/nvme0n3 /dev/nvme0n4 > /dev/null 2>&1
        check_command
        sleep 5
        
        log "Partitioning RAID 1 (MBR)..."
        sed -e 's/\s*\([\+0-9a-zA-Z]*\).*/\1/' << FDISK | fdisk /dev/md0 > /dev/null 2>&1
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
FDISK
        check_command
        partprobe /dev/md0
        sleep 2
        
        log "Formatting RAID 1 partitions..."
        mkfs.xfs -f /dev/md0p1 > /dev/null
        mkfs.xfs -f /dev/md0p5 > /dev/null
        
        log "Mounting RAID 1..."
        mkdir -p /media/nfs1 /media/nfs2
        mount /dev/md0p1 /media/nfs1
        mount /dev/md0p5 /media/nfs2
        check_command
    fi

    # --- RAID 5 Setup ---
    if [ -e /dev/md1 ]; then
        warn "RAID 5 (/dev/md1) already exists. Skipping creation."
    else
        log "Creating RAID 5 (/dev/md1)..."
        if [ ! -e /dev/nvme0n5 ]; then error_exit "Drive /dev/nvme0n5 missing for RAID 5"; fi
        
        yes | mdadm --create /dev/md1 --level=5 --raid-devices=3 /dev/nvme0n5 /dev/nvme0n6 /dev/nvme0n7 > /dev/null 2>&1
        check_command
        sleep 5
        
        log "Partitioning RAID 5 (GPT)..."
        gdisk /dev/md1 << GDISK > /dev/null 2>&1
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
GDISK
        check_command
        partprobe /dev/md1
        sleep 2
        
        log "Formatting RAID 5 partitions..."
        mkfs.xfs -f /dev/md1p1 > /dev/null
        mkfs.xfs -f /dev/md1p2 > /dev/null
        mkfs.xfs -f /dev/md1p3 > /dev/null
        
        log "Mounting RAID 5..."
        mkdir -p /media/samba1 /media/samba2 /media/samba3
        mount /dev/md1p1 /media/samba1
        mount /dev/md1p2 /media/samba2
        mount /dev/md1p3 /media/samba3
        check_command
    fi

    # --- Persistence ---
    log "Configuring Persistence (fstab)..."
    cp /etc/fstab /etc/fstab.bak
    sed -i '/media\/nfs/d' /etc/fstab
    sed -i '/media\/samba/d' /etc/fstab

    UUID_R1P1=$(blkid -s UUID -o value /dev/md0p1)
    if [ -z "$UUID_R1P1" ]; then error_exit "Could not find UUID for /dev/md0p1"; fi

    echo "UUID=$(blkid -s UUID -o value /dev/md0p1) /media/nfs1 xfs defaults 0 0" >> /etc/fstab
    echo "UUID=$(blkid -s UUID -o value /dev/md0p5) /media/nfs2 xfs defaults 0 0" >> /etc/fstab
    echo "UUID=$(blkid -s UUID -o value /dev/md1p1) /media/samba1 xfs defaults 0 0" >> /etc/fstab
    echo "UUID=$(blkid -s UUID -o value /dev/md1p2) /media/samba2 xfs defaults 0 0" >> /etc/fstab
    echo "UUID=$(blkid -s UUID -o value /dev/md1p3) /media/samba3 xfs defaults 0 0" >> /etc/fstab

    log "RAID Configuration Complete."
}

# ==============================================================================
# MODULE 2: APACHE VIRTUAL WEB SERVER (Lab 06)
# ==============================================================================
setup_webserver() {
    echo "----------------------------------------------------------------"
    log "STARTING MODULE: VIRTUAL WEB SERVER (Lab 06)"
    echo "----------------------------------------------------------------"

    DOMAIN="gpavks.com"
    VHOST1="starlord.${DOMAIN}"
    VHOST2="gamora.${DOMAIN}"

    log "Installing Apache..."
    dnf install -y httpd > /dev/null
    check_command

    log "Configuring Firewall..."
    firewall-cmd --zone=public --add-service=http --permanent > /dev/null 2>&1
    firewall-cmd --zone=public --add-service=https --permanent > /dev/null 2>&1
    firewall-cmd --reload > /dev/null 2>&1

    log "Creating directories and index files..."
    mkdir -p /www/virtualhosts/${VHOST1}
    mkdir -p /www/virtualhosts/${VHOST2}
    
    echo "<html><h1>Welcome to ${VHOST1}</h1></html>" > /www/virtualhosts/${VHOST1}/index.html
    echo "<html><h1>Welcome to ${VHOST2}</h1></html>" > /www/virtualhosts/${VHOST2}/index.html

    log "Setting permissions and SELinux context..."
    chown -R apache:apache /www
    chmod -R 755 /www
    chcon -R -t httpd_sys_content_t /www
    check_command

    HTTPD_CONF="/etc/httpd/conf/httpd.conf"
    if ! grep -q "/www/virtualhosts" "$HTTPD_CONF"; then
        log "Updating global httpd.conf..."
        cp $HTTPD_CONF ${HTTPD_CONF}.bak
        cat <<EOF >> "$HTTPD_CONF"

# Lab 06 Virtual Hosts Directory Access
<Directory "/www/virtualhosts">
    AllowOverride None
    Require all granted
</Directory>
EOF
    else
        warn "Global httpd.conf already contains virtualhosts directive. Skipping."
    fi

    log "Generating Virtual Host Configurations..."
    cat <<EOF > /etc/httpd/conf.d/${VHOST1}.conf
<VirtualHost *:80>
    ServerAdmin webmaster@${VHOST1}
    DocumentRoot /www/virtualhosts/${VHOST1}
    ServerName ${VHOST1}
    ErrorLog logs/${VHOST1}-error.log
</VirtualHost>
EOF

    cat <<EOF > /etc/httpd/conf.d/${VHOST2}.conf
<VirtualHost *:80>
    ServerAdmin webmaster@${VHOST2}
    DocumentRoot /www/virtualhosts/${VHOST2}
    ServerName ${VHOST2}
    ErrorLog logs/${VHOST2}-error.log
</VirtualHost>
EOF

    cat <<EOF > /etc/httpd/conf.d/_default_.conf
<VirtualHost *:80>
    DocumentRoot /var/www/html
</VirtualHost>
EOF

    log "Testing Apache Configuration..."
    apachectl configtest
    check_command

    log "Starting Apache..."
    systemctl enable --now httpd
    systemctl restart httpd
    check_command

    log "Web Server Configuration Complete."
}

# ==============================================================================
# MODULE 3: RSYNC DAEMON (Lab 05 - Activity 7)
# ==============================================================================
setup_rsyncd() {
    echo "----------------------------------------------------------------"
    log "STARTING MODULE: RSYNC DAEMON (Lab 05)"
    echo "----------------------------------------------------------------"

    log "Installing Rsync and daemon..."
    dnf install -y rsync > /dev/null
    dnf install -y rsync rsync-daemon > /dev/null
    check_command

    log "Opening Firewall Port 873..."
    firewall-cmd --permanent --add-port=873/tcp > /dev/null 2>&1
    firewall-cmd --reload > /dev/null 2>&1

    RSYNC_CONF="/etc/rsyncd.conf"
    if grep -q "\[ramones\]" "$RSYNC_CONF"; then
        warn "Rsync module [ramones] already exists in $RSYNC_CONF. Skipping append."
    else
        log "Configuring $RSYNC_CONF..."
        cp $RSYNC_CONF ${RSYNC_CONF}.bak
        cat <<EOF >> "$RSYNC_CONF"

[ramones]
chroot = false
path = /media/rsync
comment = Ramones RSYNC Module
read only = yes
list = yes
uid = nobody
gid = nobody
EOF
    fi

    log "Setting up shared directory..."
    if [ ! -d /media/rsync ]; then
        mkdir -p /media/rsync
    fi
    
    echo "Hey Ho, Let's Go!" > /media/rsync/test.txt
    
    log "Applying SELinux context for Rsync..."
    chcon -R -t rsync_data_t /media/rsync
    check_command

    log "Starting Rsync service..."
    systemctl enable --now rsyncd
    systemctl restart rsyncd
    check_command

    log "Rsync Daemon Configuration Complete."
}

# ==============================================================================
# MODULE 4: SAMBA FILE SHARING (Lab 05 - Activity 5)
# ==============================================================================
setup_samba() {
    echo "----------------------------------------------------------------"
    log "STARTING MODULE: SAMBA FILE SHARING (Lab 05)"
    echo "----------------------------------------------------------------"

    # --- Install Packages ---
    log "Installing Samba packages..."
    dnf install -y samba samba-common samba-client policycoreutils-python-utils > /dev/null
    check_command

    # --- Firewall ---
    log "Configuring Firewall for Samba..."
    firewall-cmd --add-service=samba --permanent > /dev/null 2>&1
    firewall-cmd --reload > /dev/null 2>&1

    # --- Directory Setup ---
    # Lab 5 uses /media/samba/ramones. We assume /media/samba exists from RAID setup.
    # If not, we create it just in case.
    SHARE_DIR="/media/samba/ramones"
    
    log "Creating shared directory: $SHARE_DIR"
    mkdir -p $SHARE_DIR
    
    # --- Group Setup ---
    # Lab 5 requires a 'writers' group [cite: 1675]
    if ! getent group writers > /dev/null; then
        log "Creating group 'writers'..."
        groupadd writers
    else
        log "Group 'writers' already exists."
    fi

    # --- Permissions ---
    # Lab 5 requires group ownership and write permissions [cite: 1696-1699]
    log "Setting directory permissions..."
    chgrp writers $SHARE_DIR
    chmod g+rwx $SHARE_DIR
    # SGID is good practice here (2770), but lab explicitly asked for chmod g+rwx
    chmod 2770 $SHARE_DIR

    # --- SELinux Context ---
    log "Setting SELinux context (samba_share_t)..."
    semanage fcontext -a -t samba_share_t "${SHARE_DIR}(/.*)?" 2>/dev/null || true
    restorecon -Rv $SHARE_DIR > /dev/null

    # --- User Creation Loop ---
    echo ""
    echo "--- Samba User Setup ---"
    echo "Lab 5 suggests creating users like: joey, johnny, deedee"
    read -p "How many Samba users do you want to create? " USER_COUNT < /dev/tty

    if [[ "$USER_COUNT" =~ ^[0-9]+$ ]]; then
        for ((i=1; i<=USER_COUNT; i++)); do
            echo ""
            read -p "Enter username #$i: " SMB_USER < /dev/tty
            
            # Create system user (nologin) 
            if id "$SMB_USER" &>/dev/null; then
                log "System user $SMB_USER already exists."
            else
                useradd -s /sbin/nologin $SMB_USER
                log "Created system user $SMB_USER"
            fi

            # Add to 'writers' group [cite: 1679]
            usermod -aG writers $SMB_USER
            log "Added $SMB_USER to 'writers' group."

            # Set Samba Password [cite: 1689]
            log "Set Samba password for $SMB_USER:"
            smbpasswd -a $SMB_USER
        done
    else
        warn "Invalid number. Skipping user creation."
    fi

    # --- Config smb.conf ---
    SMB_CONF="/etc/samba/smb.conf"
    
    if grep -q "\[ramones\]" "$SMB_CONF"; then
        warn "Share [ramones] already exists in smb.conf. Skipping config append."
    else
        log "Appending [ramones] share to $SMB_CONF..."
        # Configuration per Lab 5 
        cat <<EOF >> "$SMB_CONF"

[ramones]
comment = Blitzkrieg Bop
path = $SHARE_DIR
read only = no
write list = @writers
EOF
    fi

    # --- Validation & Start ---
    log "Validating Samba config..."
    testparm -s > /dev/null
    
    log "Starting Samba services..."
    systemctl enable --now smb nmb
    systemctl restart smb nmb
    
    log "Samba Configuration Complete."
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

check_root

# 1. RUN VS CODE SETUP AUTOMATICALLY (No options required)
setup_vscode_env

# 2. RUN MENU FOR OTHER LABS
while true; do
    echo ""
    echo "==================================================="
    echo "   ROCKY LINUX SERVER CONFIGURATION MENU"
    echo "==================================================="
    echo "1. Run RAID Setup (Lab 04)"
    echo "2. Run Virtual Web Server Setup (Lab 06)"
    echo "3. Run Rsync Daemon Setup (Lab 05)"
    echo "4. Run Samba File Sharing Setup (Lab 05)"
    echo "5. Run ALL Server Modules (1-4)"
    echo "6. Exit"
    echo "==================================================="
    
    # FIX 1: Force read from TTY to prevent infinite loop on EOF
    read -p "Select an option [1-6]: " choice < /dev/tty

    case $choice in
        1) setup_raid ;;
        2) setup_webserver ;;
        3) setup_rsyncd ;;
        4) setup_samba ;;
        5) 
           setup_raid
           setup_webserver
           setup_rsyncd
           setup_samba
           ;;
        6) 
           log "Exiting."
           exit 0 
           ;;
        *) 
           warn "Invalid option. Please try again."
           ;;
    esac
    
    echo ""
    # FIX 2: Force read from TTY here as well
    read -p "Press Enter to continue..." < /dev/tty
done