#!/usr/bin/env bash
# lab2-rocky-client.sh
# Rocky Linux Lab 2 automation with fixed DNS ordering

set -e

echo "=== Rocky Linux Lab 2 Client Setup (Fixed DNS) ==="

read -rp "Enter domain FQDN (e.g. bmw7216.com): " DOMAIN
read -rp "Enter Domain Controller IP (DNS server) (e.g. 192.168.1.2): " DCIP
read -rp "Enter domain join user (e.g. Administrator): " USER
read -rsp "Enter password for $USER: " PASS
echo

echo "[*] Updating DNS settings BEFORE realm discover..."
CON=$(nmcli -t -f NAME con show --active)

nmcli connection modify "$CON" ipv4.ignore-auto-dns yes
nmcli connection modify "$CON" ipv4.dns "$DCIP"
nmcli connection up "$CON"

echo "[*] DNS now set to:"
nmcli dev show | grep DNS

echo "[*] Installing domain join packages..."
dnf install -y realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools krb5-workstation

echo "[*] Discovering $DOMAIN ..."
realm discover "$DOMAIN" || { echo "Domain discovery failed. Check DNS."; exit 1; }

echo "[*] Joining domain..."
echo "$PASS" | realm join --user="$USER" "$DOMAIN"

echo "[*] Enabling SSSD + home directory creation..."
authselect select sssd with-mkhomedir --force
systemctl enable --now sssd

echo "[*] Testing login..."
id "$USER@$DOMAIN" || echo "Lookup failed, but join may still be valid."

echo "[+] Rocky joined to $DOMAIN successfully."
