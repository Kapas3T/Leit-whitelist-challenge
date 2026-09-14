#!/usr/bin/env bash
#
# rollback-kiosque.sh — retour a un etat reseau normal
#
set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit etre lance avec sudo." >&2
    exit 1
fi

TARGET_USER="${SUDO_USER:-}"
BACKUP_DIR="/root/kiosque-backup"

echo "==> [1/5] Suppression des regles nftables"
nft delete table inet kiosque 2>/dev/null || true
if [[ -s "$BACKUP_DIR/nftables.conf.orig" ]]; then
    cp -a "$BACKUP_DIR/nftables.conf.orig" /etc/nftables.conf
    nft -f /etc/nftables.conf 2>/dev/null || true
    echo "    /etc/nftables.conf restaure."
else
    nft flush ruleset
    systemctl disable --now nftables >/dev/null 2>&1 || true
    echo "    Ruleset vide, service nftables desactive."
fi

echo "==> [2/5] Arret de Squid"
systemctl disable --now squid >/dev/null 2>&1 || true
if [[ -f "$BACKUP_DIR/squid.conf.orig" ]]; then
    cp -a "$BACKUP_DIR/squid.conf.orig" /etc/squid/squid.conf
    echo "    squid.conf d'origine restaure."
fi

echo "==> [3/5] Suppression des policies navigateurs"
rm -f /etc/firefox/policies/policies.json
rm -f /etc/opt/chrome/policies/managed/kiosque.json
rm -f /etc/chromium/policies/managed/kiosque.json
rm -f /etc/chromium-browser/policies/managed/kiosque.json

echo "==> [4/5] Remise a zero du proxy GNOME"
if [[ -n "$TARGET_USER" ]]; then
    UID_T=$(id -u "$TARGET_USER")
    sudo -u "$TARGET_USER" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${UID_T}/bus" \
        gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null || true
fi

echo "==> [5/5] Verification"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://www.google.com || echo "000")
echo "    https://www.google.com -> HTTP $code  (200 attendu)"

echo
echo "Rollback termine. Redemarre le navigateur pour qu'il reprenne un acces direct."
