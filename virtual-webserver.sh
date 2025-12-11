#!/bin/bash
# ===============================================================
# NSSA 221 - Lab 06: Apache & Virtual Hosts
# Automates Activity 1 & 2 per Lab06_Instructions.pdf
# ===============================================================

# ---------- Root Check ----------
if [[ $EUID -ne 0 ]]; then
    echo "Run this script as root (sudo)."
    exit 1
fi

echo "===== NSSA 221 Lab 06 Setup ====="

# ---------- Activity 1: Install & Configure Apache ----------
echo "[*] Installing Apache..."
dnf install -y httpd # [cite: 54]

echo "[*] Enabling and starting Apache..."
systemctl enable --now httpd # [cite: 55]

echo "[*] Allowing HTTP traffic through firewall..."
firewall-cmd --zone=public --add-service=http --permanent # [cite: 210]
firewall-cmd --reload

# ---------- Activity 2a: Edit httpd.conf ----------
# The lab asks to add a directive to httpd.conf to allow access to /www/virtualhosts 
HTTPD_CONF="/etc/httpd/conf/httpd.conf"
if ! grep -q "/www/virtualhosts" "$HTTPD_CONF"; then
    echo "[*] Appending Directory directive to $HTTPD_CONF..."
cat <<EOF >> "$HTTPD_CONF"

# Lab 06 Activity 2a: Allow access to virtual hosts
<Directory "/www/virtualhosts">
    AllowOverride None
    Require all granted
</Directory>
EOF
else
    echo "[!] Directory directive already exists in httpd.conf, skipping."
fi

# ---------- Activity 2g: Create Default Virtual Host ----------
# The lab requires a specific file named _default_.conf 
DEFAULT_CONF="/etc/httpd/conf.d/_default_.conf"
echo "[*] Creating default virtual host ($DEFAULT_CONF)..."
cat <<EOF > "$DEFAULT_CONF"
<VirtualHost *:80>
    DocumentRoot /var/www/html
    # ServerName is usually defined globally, but can be explicit here
</VirtualHost>
EOF

# ---------- Activity 2b-f: Create Virtual Hosts ----------
read -p "How many virtual hosts do you want to create? " COUNT

for ((i=1; i<=COUNT; i++)); do
    echo ""
    echo "----- Virtual Host $i -----"
    read -p "Enter short site name (ex: starlord): " SITENAME
    read -p "Enter domain (ex: gpavks.com): " DOMAIN
    
    FQDN="${SITENAME}.${DOMAIN}"
    # Lab uses the full FQDN for the directory path 
    DOCROOT="/www/virtualhosts/${FQDN}" 
    CONF="/etc/httpd/conf.d/${FQDN}.conf" # [cite: 146]

    echo "[*] Creating document root at $DOCROOT ..."
    mkdir -p "$DOCROOT" # [cite: 178]

    # Create index.html [cite: 184]
    echo "<html><body><h1>Welcome to ${FQDN}</h1></body></html>" > "${DOCROOT}/index.html"

    echo "[*] Fixing permissions..."
    # Lab mentions checking permissions [cite: 123]
    chown -R apache:apache /www
    chmod -R 755 /www

    echo "[*] Applying SELinux context..."
    # Lab suggests permissive mode[cite: 51], but setting context is cleaner/safer.
    chcon -R -t httpd_sys_content_t /www

    echo "[*] Creating virtual host config at $CONF ..."
    # Config block matches Figure 5 in Lab 06 [cite: 166-172]
cat <<EOF > "$CONF"
<VirtualHost *:80>
    ServerAdmin webmaster@${FQDN}
    DocumentRoot ${DOCROOT}
    ServerName ${FQDN}
    ErrorLog logs/${FQDN}-error.log
</VirtualHost>
EOF

    echo "[+] Virtual host ${FQDN} created."
done

# ---------- Restart Apache ----------
echo "[*] Restarting Apache to apply changes..."
systemctl restart httpd # [cite: 92]

echo ""
echo "======================================================"
echo " Configuration complete."
echo " Verify your sites by updating your local /etc/hosts"
echo " or Windows DNS as per Activity 2k[cite: 211]."
echo "======================================================"