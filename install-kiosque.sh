#!/usr/bin/env bash
#
# install-kiosque.sh — The Whitelist Challenge
#
# Met en place :
#   - Squid en liste blanche de domaines sur 127.0.0.1:3128
#   - des policies navigateur verrouillant le proxy et desactivant DoH/QUIC
#   - des regles nftables interdisant toute sortie directe aux UID >= 1000
#
# Sauvegarde l'etat anterieur dans /root/kiosque-backup/
# Rollback : ./rollback-kiosque.sh
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit etre lance avec sudo." >&2
    exit 1
fi

TARGET_USER="${SUDO_USER:-}"
BACKUP_DIR="/root/kiosque-backup"
mkdir -p "$BACKUP_DIR"

echo "==> [1/6] Sauvegarde de l'etat actuel dans $BACKUP_DIR"
nft list ruleset > "$BACKUP_DIR/nftables.before.rules" 2>/dev/null || true
[[ -f /etc/squid/squid.conf ]]  && cp -a /etc/squid/squid.conf  "$BACKUP_DIR/squid.conf.orig"
[[ -f /etc/nftables.conf ]]     && cp -a /etc/nftables.conf     "$BACKUP_DIR/nftables.conf.orig"

echo "==> [2/6] Installation des paquets (squid, nftables)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y squid nftables >/dev/null

echo "==> [3/6] Ecriture de la liste blanche /etc/squid/whitelist.txt"
cat > /etc/squid/whitelist.txt <<'EOF'
# Une entree prefixee d'un point couvre le domaine ET tous ses sous-domaines.
# Verifier/completer avec :  tail -f /var/log/squid/access.log | grep TCP_DENIED

# ================= a) galaxus.ch =================
.galaxus.ch
.digitecgalaxus.ch

# ================= b) youtube.ch =================
.youtube.ch
.youtube.com
.youtu.be
.youtube-nocookie.com
.ytimg.com
.ggpht.com
.googlevideo.com
.googleusercontent.com
www.gstatic.com
fonts.gstatic.com
fonts.googleapis.com
jnn-pa.googleapis.com

# ================= c) notion.com =================
.notion.com
.notion.so
.notion-static.com
.notionusercontent.com
prod-files-secure.s3.us-west-2.amazonaws.com

# NON autorises volontairement :
#   .google.com / .googleapis.com / .amazonaws.com  -> trop larges
#   doubleclick.net, googleadservices.com, google-analytics.com,
#   googlesyndication.com                           -> publicite / telemetrie
EOF
chown root:proxy /etc/squid/whitelist.txt
chmod 0644 /etc/squid/whitelist.txt

echo "==> [4/6] Configuration de Squid"
cat > /etc/squid/squid.conf <<'EOF'
# /etc/squid/squid.conf — kiosque liste blanche
http_port 127.0.0.1:3128

acl localnet   src 127.0.0.1/32
acl Safe_ports port 80
acl Safe_ports port 443
acl SSL_ports  port 443
acl CONNECT    method CONNECT
acl whitelist  dstdomain "/etc/squid/whitelist.txt"

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager

# --- coeur du dispositif ---
http_access allow localnet whitelist
http_access deny all

cache deny all
access_log /var/log/squid/access.log squid
via off
forwarded_for delete
httpd_suppress_version_string on
visible_hostname kiosque
EOF

squid -k parse
systemctl enable squid >/dev/null 2>&1 || true
systemctl restart squid
echo "    Squid : $(systemctl is-active squid)"

echo "==> [5/6] Policies navigateurs"
# --- Firefox (y compris le snap Ubuntu) ---
install -d /etc/firefox/policies
cat > /etc/firefox/policies/policies.json <<'EOF'
{
  "policies": {
    "Proxy": {
      "Mode": "manual",
      "HTTPProxy": "127.0.0.1:3128",
      "SSLProxy": "127.0.0.1:3128",
      "UseHTTPProxyForAllProtocols": true,
      "UseProxyForDNS": true,
      "Locked": true
    },
    "DNSOverHTTPS": {
      "Enabled": false,
      "Locked": true
    },
    "BlockAboutConfig": true,
    "DisableTelemetry": true
  }
}
EOF

# --- Chrome / Chromium ---
CHROME_POLICY='{
  "ProxyMode": "fixed_servers",
  "ProxyServer": "127.0.0.1:3128",
  "QuicAllowed": false,
  "BuiltInDnsClientEnabled": false,
  "DnsOverHttpsMode": "off"
}'
for d in /etc/opt/chrome/policies/managed \
         /etc/chromium/policies/managed \
         /etc/chromium-browser/policies/managed; do
    install -d "$d"
    printf '%s\n' "$CHROME_POLICY" > "$d/kiosque.json"
done

# --- Proxy GNOME pour les applications de la session ---
if [[ -n "$TARGET_USER" ]]; then
    UID_T=$(id -u "$TARGET_USER")
    run_gs() { sudo -u "$TARGET_USER" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${UID_T}/bus" \
        gsettings "$@" 2>/dev/null || true; }
    run_gs set org.gnome.system.proxy mode 'manual'
    run_gs set org.gnome.system.proxy.http  host '127.0.0.1'
    run_gs set org.gnome.system.proxy.http  port 3128
    run_gs set org.gnome.system.proxy.https host '127.0.0.1'
    run_gs set org.gnome.system.proxy.https port 3128
fi

echo "==> [6/6] Regles nftables"
PROXY_UID=$(id -u proxy)
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# /etc/nftables.conf — kiosque liste blanche
# Principe : les daemons systeme (UID 0, _apt, systemd-*) gardent un acces
# reseau normal (SSH et mises a jour hors perimetre). Les comptes humains
# (UID >= 1000) n'ont aucune sortie directe : seul le proxy local est joignable.
flush ruleset

table inet kiosque {
    chain output {
        type filter hook output priority filter; policy accept;

        # boucle locale : indispensable pour joindre Squid sur 127.0.0.1:3128
        oif "lo" accept

        # ne pas couper les connexions deja etablies (ex. session SSH en cours)
        ct state established,related accept

        # Squid doit pouvoir sortir
        meta skuid ${PROXY_UID} accept

        # tout compte utilisateur : aucune sortie directe, tous protocoles
        meta skuid 1000-60000 counter drop
    }
}
EOF

systemctl enable nftables >/dev/null 2>&1 || true
nft -f /etc/nftables.conf
systemctl restart nftables

echo
echo "============================================================"
echo " Installation terminee."
echo
echo " Squid      : $(systemctl is-active squid)  (127.0.0.1:3128)"
echo " nftables   : $(systemctl is-active nftables)"
echo " Whitelist  : /etc/squid/whitelist.txt"
echo " Sauvegarde : $BACKUP_DIR"
echo
echo " >>> FERME ET ROUVRE TA SESSION (ou au moins le navigateur)."
echo
echo " Pour decouvrir les domaines encore manquants pendant les tests :"
echo "   sudo tail -f /var/log/squid/access.log | grep TCP_DENIED"
echo " Puis, apres modification de la liste :"
echo "   sudo squid -k parse && sudo squid -k reconfigure"
echo
echo " Rollback : sudo ./rollback-kiosque.sh"
echo "============================================================"
