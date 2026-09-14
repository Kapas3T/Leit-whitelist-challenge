#!/usr/bin/env bash
#
# kiosque.sh — assistant de mise en place d'une liste blanche de navigation
#
#   1. demande quels sites doivent rester accessibles
#   2. découvre automatiquement les domaines annexes nécessaires
#   3. propose la liste à la validation de l'installateur
#   4. applique le proxy Squid + le pare-feu nftables
#
# Usage : sudo ./kiosque.sh            (menu interactif)
#         sudo ./kiosque.sh <commande> (configurer|apprendre|recolter|tester|
#                                       appliquer|statut|rollback)
#
set -uo pipefail

WHITELIST="/etc/squid/whitelist.txt"
SEEDS="/etc/squid/kiosque-seeds.txt"
SQUID_CONF="/etc/squid/squid.conf"
MODE_FILE="/etc/squid/.kiosque-mode"
NFT_CONF="/etc/nftables.conf"
BACKUP_DIR="/root/kiosque-backup"
ACCESS_LOG="/var/log/squid/access.log"
PROXY="http://127.0.0.1:3128"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
RUN_USER="${SUDO_USER:-}"

# Domaines publicitaires / télémétrie : jamais proposés à l'ajout.
AD_DOMAINS="doubleclick.net googleadservices.com googlesyndication.com
google-analytics.com googletagmanager.com adservice.google.com
scorecardresearch.com criteo.com taboola.com outbrain.com hotjar.com
mixpanel.com amplitude.com segment.com sentry.io newrelic.com adnxs.com
pubmatic.com rubiconproject.com casalemedia.com facebook.net"

# Bruit de parsing (namespaces XML, etc.) : jamais proposé non plus.
NOISE_DOMAINS="w3.org schema.org ogp.me purl.org example.com localhost"

# Suffixes à deux niveaux, pour ne pas réduire "bbc.co.uk" à "co.uk".
TWO_LEVEL_TLDS="co.uk ac.uk org.uk gov.uk com.au net.au org.au co.nz co.jp
com.br com.mx co.za com.tr co.in com.sg"

# Connaissances métier : compagnons connus de quelques grands sites.
# Complète librement cette table, c'est le point d'extension du script.
hints_for() {
    case "$1" in
        youtube.com|youtube.ch|youtu.be)
            echo "youtube.com youtube.ch youtu.be youtube-nocookie.com \
                  googlevideo.com ytimg.com ggpht.com googleusercontent.com \
                  gstatic.com jnn-pa.googleapis.com" ;;
        notion.com|notion.so)
            echo "notion.com notion.so notion-static.com notionusercontent.com" ;;
        galaxus.ch|digitec.ch)
            echo "galaxus.ch digitec.ch digitecgalaxus.ch" ;;
        google.com|gmail.com)
            echo "google.com gstatic.com googleusercontent.com googleapis.com" ;;
        wikipedia.org)
            echo "wikipedia.org wikimedia.org wikimediafoundation.org" ;;
        *) : ;;
    esac
}

# ---------------------------------------------------------------- utilitaires

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
c_err()  { printf '\033[31m%s\033[0m\n' "$*"; }
c_head() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

require_root() {
    [[ $EUID -eq 0 ]] || { c_err "Lance ce script avec sudo."; exit 1; }
}

runas_user() {
    # exécute une commande sous le compte utilisateur (donc soumis au pare-feu)
    if [[ -n "$RUN_USER" ]]; then sudo -u "$RUN_USER" "$@"; else "$@"; fi
}

in_list() {
    local needle="$1"; shift
    local item
    for item in $*; do [[ "$item" == "$needle" ]] && return 0; done
    return 1
}

# Réduit un nom d'hôte à son domaine enregistrable (www.a.b.ch -> b.ch)
registrable() {
    local h="${1,,}"; h="${h%.}"
    local n; n=$(awk -F. '{print NF}' <<<"$h")
    (( n <= 2 )) && { echo "$h"; return; }
    local last2; last2=$(cut -d. -f$((n-1))-"$n" <<<"$h")
    if [[ " $(echo $TWO_LEVEL_TLDS) " == *" $last2 "* ]]; then
        cut -d. -f$((n-2))-"$n" <<<"$h"
    else
        echo "$last2"
    fi
}

backup_once() {
    mkdir -p "$BACKUP_DIR"
    [[ -f "$BACKUP_DIR/nftables.before.rules" ]] || \
        nft list ruleset > "$BACKUP_DIR/nftables.before.rules" 2>/dev/null
    [[ -f "$BACKUP_DIR/squid.conf.orig" || ! -f "$SQUID_CONF" ]] || \
        cp -a "$SQUID_CONF" "$BACKUP_DIR/squid.conf.orig"
    [[ -f "$BACKUP_DIR/nftables.conf.orig" || ! -f "$NFT_CONF" ]] || \
        cp -a "$NFT_CONF" "$BACKUP_DIR/nftables.conf.orig"
}

ensure_packages() {
    if ! command -v squid >/dev/null || ! command -v nft >/dev/null; then
        c_head "Installation de squid et nftables"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y squid nftables
    fi
}

# ----------------------------------------------------------------- découverte

# Extrait les noms d'hôtes d'un flux HTML/JSON passé sur stdin
extract_hosts() {
    grep -oE '//[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,24}' \
      | sed 's|^//||' | tr 'A-Z' 'a-z' | sort -u
}

# Découvre les domaines liés à un site : redirections, HTML, preconnect,
# table de connaissances, et (si disponible) chargement headless réel.
discover() {
    local seed="$1"
    local out="" host final html chrome netlog tmpdir

    out+=" $seed www.$seed"

    # 1. suivre les redirections (youtube.ch -> www.youtube.com)
    for host in "$seed" "www.$seed"; do
        final=$(curl -sIL -A "$UA" --max-time 15 -o /dev/null \
                     -w '%{url_effective}' "https://$host" 2>/dev/null)
        [[ -n "$final" ]] && out+=" $(sed -E 's|^[a-z]+://||; s|/.*$||; s|:[0-9]+$||' <<<"$final")"
    done

    # 2. analyse statique du HTML (src, href, preconnect, dns-prefetch)
    for host in "$seed" "www.$seed"; do
        html=$(curl -sL -A "$UA" --max-time 20 "https://$host" 2>/dev/null)
        [[ -n "$html" ]] && out+=" $(extract_hosts <<<"$html" | tr '\n' ' ')" && break
    done

    # 3. chargement réel en navigateur headless, si Chrome/Chromium est présent
    chrome=$(command -v chromium google-chrome chromium-browser 2>/dev/null | head -1)
    if [[ -n "$chrome" ]]; then
        tmpdir=$(mktemp -d); netlog="$tmpdir/net.json"
        timeout 60 "$chrome" --headless=new --disable-gpu --no-sandbox \
            --user-data-dir="$tmpdir/profile" --log-net-log="$netlog" \
            --net-log-capture-mode=Default --virtual-time-budget=20000 \
            "https://$seed" >/dev/null 2>&1
        [[ -s "$netlog" ]] && out+=" $(extract_hosts <"$netlog" | tr '\n' ' ')"
        rm -rf "$tmpdir"
    fi

    # 4. table de connaissances
    out+=" $(hints_for "$seed")"
    out+=" $(hints_for "$(registrable "$seed")")"

    # normalisation : domaine enregistrable, filtrage pub/bruit
    local h r
    for h in $out; do
        [[ "$h" =~ ^[a-z0-9.-]+\.[a-z]{2,24}$ ]] || continue
        r=$(registrable "$h")
        in_list "$r" "$AD_DOMAINS"    && continue
        in_list "$r" "$NOISE_DOMAINS" && continue
        # un hôte précis à 3+ labels issu de la table de hints est gardé tel quel
        if [[ "$h" == *.*.* ]] && in_list "$h" "$(hints_for "$seed") $(hints_for "$(registrable "$seed")")"; then
            echo "$h"
        else
            echo "$r"
        fi
    done | sort -u
}

# ------------------------------------------------------------------- fichiers

write_whitelist() {
    # stdin : une entrée par ligne (sans point initial)
    { echo "# Liste blanche générée par kiosque.sh le $(date '+%F %T')"
      echo "# Une entrée préfixée d'un point couvre le domaine et ses sous-domaines."
      echo "# Rechargement à chaud : squid -k parse && squid -k reconfigure"
      echo
      sed -E 's/^\.?/./' | sort -u
    } > "$WHITELIST"
    chmod 644 "$WHITELIST"
}

write_squid_conf() {
    local mode="$1" access_line
    if [[ "$mode" == "learn" ]]; then
        access_line="http_access allow localnet   # MODE APPRENTISSAGE : tout passe, tout est journalisé"
    else
        access_line="http_access allow localnet whitelist"
    fi
    cat > "$SQUID_CONF" <<EOF
# /etc/squid/squid.conf — généré par kiosque.sh (mode: $mode)
http_port 127.0.0.1:3128

acl localnet   src 127.0.0.1/32
acl Safe_ports port 80
acl Safe_ports port 443
acl SSL_ports  port 443
acl CONNECT    method CONNECT
acl whitelist  dstdomain "$WHITELIST"

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager

# --- coeur du dispositif ---
$access_line
http_access deny all

cache deny all
access_log $ACCESS_LOG squid
via off
forwarded_for delete
httpd_suppress_version_string on
visible_hostname kiosque
EOF
    echo "$mode" > "$MODE_FILE"
    squid -k parse || { c_err "Configuration Squid invalide."; return 1; }
    systemctl enable squid >/dev/null 2>&1
    systemctl restart squid
}

write_browser_policies() {
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
    "DNSOverHTTPS": { "Enabled": false, "Locked": true },
    "BlockAboutConfig": true
  }
}
EOF
    local pol='{
  "ProxyMode": "fixed_servers",
  "ProxyServer": "127.0.0.1:3128",
  "QuicAllowed": false,
  "BuiltInDnsClientEnabled": false,
  "DnsOverHttpsMode": "off"
}'
    local d
    for d in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed \
             /etc/chromium-browser/policies/managed; do
        install -d "$d"; printf '%s\n' "$pol" > "$d/kiosque.json"
    done

    if [[ -n "$RUN_USER" ]]; then
        local uid; uid=$(id -u "$RUN_USER")
        local env="DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus"
        sudo -u "$RUN_USER" env $env gsettings set org.gnome.system.proxy mode 'manual' 2>/dev/null
        sudo -u "$RUN_USER" env $env gsettings set org.gnome.system.proxy.http  host '127.0.0.1' 2>/dev/null
        sudo -u "$RUN_USER" env $env gsettings set org.gnome.system.proxy.http  port 3128 2>/dev/null
        sudo -u "$RUN_USER" env $env gsettings set org.gnome.system.proxy.https host '127.0.0.1' 2>/dev/null
        sudo -u "$RUN_USER" env $env gsettings set org.gnome.system.proxy.https port 3128 2>/dev/null
    fi
}

# ------------------------------------------------------------------ commandes

cmd_configure() {
    require_root; backup_once; ensure_packages

    c_head "Quels sites doivent rester accessibles ?"
    echo "Saisis un domaine par ligne (ex. galaxus.ch). Ligne vide pour terminer."
    local sites=() line
    while true; do
        read -r -p "  site> " line
        line=$(sed -E 's|^[a-z]+://||; s|/.*$||; s|^www\.||; s/[[:space:]]//g' <<<"${line,,}")
        [[ -z "$line" ]] && break
        [[ "$line" =~ ^[a-z0-9.-]+\.[a-z]{2,24}$ ]] || { c_warn "  domaine invalide, ignoré"; continue; }
        sites+=("$line"); c_ok "  + $line"
    done
    [[ ${#sites[@]} -eq 0 ]] && { c_err "Aucun site saisi."; return 1; }

    printf '%s\n' "${sites[@]}" | sort -u > "$SEEDS"

    c_head "Découverte des domaines annexes"
    echo "(redirections, HTML, preconnect, rendu headless, table de connaissances)"
    local all="" s
    for s in "${sites[@]}"; do
        printf '  %-28s ' "$s"
        local found; found=$(discover "$s" | tr '\n' ' ')
        all+=" $found"
        echo "$(wc -w <<<"$found") domaine(s)"
    done

    local proposal; proposal=$(mktemp /tmp/kiosque-whitelist.XXXX)
    { echo "# Vérifie cette liste : supprime ce qui est inutile, ajoute ce qui manque."
      echo "# Une ligne = un domaine. Les lignes commençant par # sont ignorées."
      echo
      tr ' ' '\n' <<<"$all" | grep -v '^$' | sort -u
    } > "$proposal"

    c_head "Validation de la liste"
    echo "Ouverture de l'éditeur. Relis chaque ligne : c'est ce que tu devras"
    echo "justifier devant le formateur."
    read -r -p "Entrée pour continuer..."
    "${EDITOR:-nano}" "$proposal"

    grep -vE '^\s*(#|$)' "$proposal" | write_whitelist
    rm -f "$proposal"

    c_head "Liste blanche retenue"
    grep -v '^#' "$WHITELIST" | grep -v '^$' | sed 's/^/  /'

    write_squid_conf enforce || return 1
    write_browser_policies
    c_ok "\nProxy actif. Redémarre le navigateur, puis lance 'tester'."
    c_warn "Le pare-feu n'est pas encore actif : le proxy reste contournable."
    c_warn "Utilise 'appliquer' une fois que les sites fonctionnent."
}

cmd_learn() {
    require_root; ensure_packages
    c_head "Mode apprentissage"
    echo "Squid va TOUT autoriser, mais journaliser chaque domaine demandé."
    echo "Navigue ensuite normalement sur tes sites autorisés — et uniquement"
    echo "sur eux — en utilisant vraiment leurs fonctions (vidéo, recherche,"
    echo "connexion, upload). Reviens ensuite lancer 'recolter'."
    read -r -p "Continuer ? [o/N] " a; [[ "${a,,}" == "o" ]] || return 0
    : > "$ACCESS_LOG"
    write_squid_conf learn && c_ok "Mode apprentissage actif."
    write_browser_policies
    c_warn "N'oublie pas de repasser en mode strict avec 'recolter' puis 'appliquer'."
}

cmd_harvest() {
    require_root
    [[ -s "$ACCESS_LOG" ]] || { c_err "Journal vide : rien à récolter."; return 1; }

    c_head "Domaines observés dans le journal"
    local seen; seen=$(awk '{print $7}' "$ACCESS_LOG" \
        | sed -E 's|^[a-z]+://||; s|/.*$||; s|:[0-9]+$||' \
        | grep -E '^[a-z0-9.-]+\.[a-z]{2,24}$' | tr 'A-Z' 'a-z' | sort -u)

    local current; current=$(grep -v '^#' "$WHITELIST" 2>/dev/null | sed 's/^\.//' | grep -v '^$')
    local proposal; proposal=$(mktemp /tmp/kiosque-whitelist.XXXX)

    { echo "# Liste actuelle + domaines observés pendant l'apprentissage."
      echo "# Supprime les domaines publicitaires ou inutiles avant d'enregistrer."
      echo
      { echo "$current"; echo "$seen"; } | grep -v '^$' | sort -u
    } > "$proposal"

    echo "  $(wc -l <<<"$seen") domaine(s) observé(s), $(wc -l <<<"$current") déjà en liste."
    read -r -p "Entrée pour relire la liste fusionnée..."
    "${EDITOR:-nano}" "$proposal"

    grep -vE '^\s*(#|$)' "$proposal" | write_whitelist
    rm -f "$proposal"
    write_squid_conf enforce && c_ok "Mode strict réactivé avec la liste mise à jour."
}

cmd_test() {
    require_root
    [[ -s "$SEEDS" ]] || { c_err "Aucun site configuré."; return 1; }

    c_head "Sites autorisés (doivent répondre 200)"
    local s code
    while read -r s; do
        code=$(curl -x "$PROXY" -sL -o /dev/null -w '%{http_code}' \
                    -A "$UA" --max-time 20 "https://$s")
        [[ "$code" == "200" ]] && c_ok "  $s -> $code" || c_err "  $s -> $code"
    done < "$SEEDS"

    c_head "Sites hors liste (doivent échouer)"
    for s in www.google.com www.facebook.com fr.wikipedia.org duckduckgo.com; do
        code=$(curl -x "$PROXY" -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$s")
        [[ "$code" == "200" ]] && c_err "  $s -> $code  (NON BLOQUÉ !)" || c_ok "  $s -> bloqué ($code)"
    done

    c_head "Contournements (depuis le compte utilisateur)"
    if runas_user curl -s -o /dev/null --max-time 8 https://1.1.1.1 2>/dev/null; then
        c_err "  sortie directe par IP : POSSIBLE — le pare-feu n'est pas actif"
    else
        c_ok "  sortie directe par IP : bloquée"
    fi
    if runas_user curl -s -o /dev/null --max-time 8 https://www.google.com 2>/dev/null; then
        c_err "  sortie directe sans proxy : POSSIBLE — le pare-feu n'est pas actif"
    else
        c_ok "  sortie directe sans proxy : bloquée"
    fi

    c_head "Hors périmètre (doit continuer à fonctionner)"
    apt-get update -qq >/dev/null 2>&1 && c_ok "  apt update : ok" || c_warn "  apt update : échec"
}

cmd_enforce() {
    require_root; backup_once
    local proxy_uid; proxy_uid=$(id -u proxy)

    c_head "Activation du pare-feu"
    echo "Toute sortie réseau directe sera coupée pour les comptes UID >= 1000."
    echo "Les daemons système (root, _apt, systemd-*) ne sont pas filtrés :"
    echo "SSH et les mises à jour restent hors périmètre."
    c_warn "Commande de secours si tu te coupes le réseau : sudo nft flush ruleset"
    read -r -p "Continuer ? [o/N] " a; [[ "${a,,}" == "o" ]] || return 0

    cat > "$NFT_CONF" <<EOF
#!/usr/sbin/nft -f
# Généré par kiosque.sh le $(date '+%F %T')
flush ruleset

table inet kiosque {
    chain output {
        type filter hook output priority filter; policy accept;

        # boucle locale : indispensable pour joindre Squid sur 127.0.0.1:3128
        oif "lo" accept

        # ne pas couper les connexions déjà établies (ex. session SSH en cours)
        ct state established,related accept

        # Squid doit pouvoir sortir (UID $proxy_uid)
        meta skuid $proxy_uid accept

        # comptes utilisateurs : aucune sortie directe, tous protocoles
        meta skuid 1000-60000 counter drop
    }
}
EOF
    nft -f "$NFT_CONF" && systemctl enable nftables >/dev/null 2>&1 \
        && c_ok "Pare-feu actif et persistant." || c_err "Échec de l'application."
}

cmd_status() {
    c_head "État"
    printf '  squid      : %s\n' "$(systemctl is-active squid 2>/dev/null)"
    printf '  nftables   : %s\n' "$(systemctl is-active nftables 2>/dev/null)"
    printf '  mode squid : %s\n' "$(cat "$MODE_FILE" 2>/dev/null || echo 'non configuré')"
    printf '  sites      : %s\n' "$(tr '\n' ' ' < "$SEEDS" 2>/dev/null)"
    printf '  whitelist  : %s entrée(s)\n' "$(grep -cvE '^\s*(#|$)' "$WHITELIST" 2>/dev/null || echo 0)"
    if nft list table inet kiosque >/dev/null 2>&1; then
        c_head "Paquets bloqués par le pare-feu"
        nft list table inet kiosque | grep -E 'counter' | sed 's/^/  /'
    fi
    c_head "Derniers refus du proxy"
    grep TCP_DENIED "$ACCESS_LOG" 2>/dev/null | tail -10 | awk '{print "  "$7}'
}

cmd_rollback() {
    require_root
    c_head "Retour à un état réseau normal"
    nft delete table inet kiosque 2>/dev/null
    if [[ -s "$BACKUP_DIR/nftables.conf.orig" ]]; then
        cp -a "$BACKUP_DIR/nftables.conf.orig" "$NFT_CONF"; nft -f "$NFT_CONF" 2>/dev/null
    else
        nft flush ruleset; systemctl disable --now nftables >/dev/null 2>&1
    fi
    systemctl disable --now squid >/dev/null 2>&1
    [[ -f "$BACKUP_DIR/squid.conf.orig" ]] && cp -a "$BACKUP_DIR/squid.conf.orig" "$SQUID_CONF"
    rm -f /etc/firefox/policies/policies.json \
          /etc/opt/chrome/policies/managed/kiosque.json \
          /etc/chromium/policies/managed/kiosque.json \
          /etc/chromium-browser/policies/managed/kiosque.json "$MODE_FILE"
    if [[ -n "$RUN_USER" ]]; then
        local uid; uid=$(id -u "$RUN_USER")
        sudo -u "$RUN_USER" env "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" \
            gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null
    fi
    local code; code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://www.google.com)
    [[ "$code" == "200" ]] && c_ok "Réseau normal rétabli (google.com -> 200)." \
                           || c_warn "Vérifie manuellement (google.com -> $code)."
}

# ----------------------------------------------------------------------- menu

menu() {
    while true; do
        cat <<'EOF'

┌─────────────────────────────────────────────────────────┐
│  kiosque.sh — liste blanche de navigation               │
├─────────────────────────────────────────────────────────┤
│  1) configurer  saisir les sites + découverte auto      │
│  2) apprendre   mode permissif qui journalise tout      │
│  3) recolter    ajouter les domaines vus + mode strict  │
│  4) tester      valider autorisés / bloqués / bypass    │
│  5) appliquer   activer le pare-feu (enforcement)       │
│  6) statut      état du dispositif                      │
│  7) rollback    revenir à un réseau normal              │
│  0) quitter                                             │
└─────────────────────────────────────────────────────────┘
EOF
        read -r -p "Choix > " c
        case "$c" in
            1) cmd_configure ;; 2) cmd_learn ;; 3) cmd_harvest ;;
            4) cmd_test ;; 5) cmd_enforce ;; 6) cmd_status ;;
            7) cmd_rollback ;; 0) exit 0 ;;
            *) c_warn "Choix invalide." ;;
        esac
    done
}

case "${1:-menu}" in
    configurer|configure) cmd_configure ;;
    apprendre|learn)      cmd_learn ;;
    recolter|harvest)     cmd_harvest ;;
    tester|test)          cmd_test ;;
    appliquer|enforce)    cmd_enforce ;;
    statut|status)        cmd_status ;;
    rollback)             cmd_rollback ;;
    menu)                 menu ;;
    *) echo "Usage: $0 [configurer|apprendre|recolter|tester|appliquer|statut|rollback]" ;;
esac
