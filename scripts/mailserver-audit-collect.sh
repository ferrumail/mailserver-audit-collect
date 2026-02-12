#!/bin/bash
#
# mailserver-audit-collect.sh
# Raccolta configurazioni mailserver per audit
# Supporta: Postfix, Exim (MTA) / Dovecot, Cyrus (MDA)
#
# Versione: 2.0
# Uso: sudo ./mailserver-audit-collect.sh
#
# Modifiche v2.0:
# - Aggiunto doveconf -P (password nascoste) e -N (include plugin)
# - Aggiunta raccolta regole firewall (iptables, nftables, firewalld)
# - Aggiunta raccolta timestamp per verifica coerenza config vs servizio
#

set -u

SCRIPT_VERSION="2.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
OUTDIR="mailaudit_${HOSTNAME}_${TIMESTAMP}"

# Porte mail per filtri
MAIL_PORTS="25|465|587|110|995|143|993|4190"

# Colori per output (se terminale)
if [ -t 1 ]; then
    C_GREEN='\033[0;32m'
    C_YELLOW='\033[0;33m'
    C_RED='\033[0;31m'
    C_RESET='\033[0m'
else
    C_GREEN=''
    C_YELLOW=''
    C_RED=''
    C_RESET=''
fi

log_info()  { echo -e "${C_GREEN}[INFO]${C_RESET} $1"; }
log_warn()  { echo -e "${C_YELLOW}[WARN]${C_RESET} $1"; }
log_error() { echo -e "${C_RED}[ERROR]${C_RESET} $1"; }

# Verifica root
if [ "$(id -u)" -ne 0 ]; then
    log_error "Eseguire come root: sudo $0"
    exit 1
fi

mkdir -p "$OUTDIR"
log_info "Output directory: $OUTDIR"

# File di riepilogo
SUMMARY="$OUTDIR/00_summary.txt"
{
    echo "Mailserver Audit Collection"
    echo "==========================="
    echo "Script versione: $SCRIPT_VERSION"
    echo "Hostname: $HOSTNAME"
    echo "Data raccolta: $(date -Is)"
    echo "Epoch raccolta: $(date +%s)"
    echo "Utente: $(whoami)"
    echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo "Kernel: $(uname -r)"
    echo ""
} > "$SUMMARY"

# Funzione per copiare file/directory se esistono
collect_path() {
    local src="$1"
    local dest_subdir="$2"
    local dest="$OUTDIR/$dest_subdir"
    
    if [ -e "$src" ]; then
        mkdir -p "$dest"
        cp -a "$src" "$dest/" 2>/dev/null
        log_info "Raccolto: $src"
        return 0
    fi
    return 1
}

# Funzione per salvare output comando
collect_cmd() {
    local desc="$1"
    local outfile="$2"
    shift 2
    local cmd="$*"
    
    # Estrae il primo token per verificare se il comando esiste
    local first_cmd
    first_cmd=$(echo "$cmd" | awk '{print $1}')
    
    if command -v "$first_cmd" >/dev/null 2>&1; then
        {
            echo "# Comando: $cmd"
            echo "# Data: $(date -Is)"
            echo "# ---"
            eval "$cmd" 2>&1
        } > "$OUTDIR/$outfile"
        log_info "$desc -> $outfile"
        return 0
    fi
    return 1
}

#############################################
# RILEVAMENTO COMPONENTI
#############################################

MTA_FOUND=""
MDA_FOUND=""

# Rileva MTA
if command -v postconf >/dev/null 2>&1; then
    MTA_FOUND="postfix"
elif command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
    MTA_FOUND="exim"
fi

# Rileva MDA
if command -v doveconf >/dev/null 2>&1; then
    MDA_FOUND="dovecot"
elif command -v imapd >/dev/null 2>&1 || [ -f /etc/imapd.conf ]; then
    MDA_FOUND="cyrus"
fi

{
    echo "MTA rilevato: ${MTA_FOUND:-NESSUNO}"
    echo "MDA rilevato: ${MDA_FOUND:-NESSUNO}"
    echo ""
} >> "$SUMMARY"

if [ -z "$MTA_FOUND" ] && [ -z "$MDA_FOUND" ]; then
    log_error "Nessun mailserver rilevato"
    exit 1
fi

#############################################
# POSTFIX
#############################################

if [ "$MTA_FOUND" = "postfix" ]; then
    log_info "=== Raccolta Postfix ==="
    
    mkdir -p "$OUTDIR/postfix/config_files"
    mkdir -p "$OUTDIR/postfix/config_active"
    
    # Versione
    collect_cmd "Postfix versione" "postfix/version.txt" postconf mail_version
    
    # File di configurazione
    for f in /etc/postfix/main.cf \
             /etc/postfix/master.cf \
             /etc/postfix/dynamicmaps.cf \
             /etc/postfix/*.regexp \
             /etc/postfix/*.pcre \
             /etc/postfix/*.cidr; do
        [ -f "$f" ] && cp "$f" "$OUTDIR/postfix/config_files/" 2>/dev/null
    done
    
    # Tabelle (hash, btree) - copia solo .cf, non .db
    for f in /etc/postfix/*.cf /etc/postfix/sasl/*.cf; do
        [ -f "$f" ] && cp "$f" "$OUTDIR/postfix/config_files/" 2>/dev/null
    done
    
    log_info "Raccolti file config Postfix"
    
    # Configurazione attiva
    collect_cmd "Postfix config attiva (non-default)" \
        "postfix/config_active/postconf_n.txt" \
        postconf -n
    
    collect_cmd "Postfix config completa" \
        "postfix/config_active/postconf_full.txt" \
        postconf
    
    collect_cmd "Postfix master.cf attivo" \
        "postfix/config_active/master_cf_active.txt" \
        postconf -M
    
    # TLS
    collect_cmd "Postfix TLS config" \
        "postfix/config_active/tls_config.txt" \
        "postconf | grep -i tls"
    
    # SASL
    collect_cmd "Postfix SASL config" \
        "postfix/config_active/sasl_config.txt" \
        "postconf | grep -i sasl"
    
    # Stato
    collect_cmd "Postfix stato coda" \
        "postfix/queue_status.txt" \
        postqueue -p
    
    echo "Postfix: OK" >> "$SUMMARY"
fi

#############################################
# EXIM
#############################################

if [ "$MTA_FOUND" = "exim" ]; then
    log_info "=== Raccolta Exim ==="
    
    # Determina comando (exim vs exim4 su Debian)
    EXIM_CMD="exim"
    command -v exim4 >/dev/null 2>&1 && EXIM_CMD="exim4"
    
    mkdir -p "$OUTDIR/exim/config_files"
    mkdir -p "$OUTDIR/exim/config_active"
    
    # Versione e build
    collect_cmd "Exim versione" "exim/version.txt" "$EXIM_CMD -bV"
    
    # File di configurazione - varia per distribuzione
    # Debian/Ubuntu: /etc/exim4/
    # RHEL/CentOS: /etc/exim/
    for confdir in /etc/exim4 /etc/exim; do
        if [ -d "$confdir" ]; then
            cp -a "$confdir"/* "$OUTDIR/exim/config_files/" 2>/dev/null
            log_info "Raccolti file config da $confdir"
        fi
    done
    
    # Configurazione attiva (espansa)
    collect_cmd "Exim config attiva" \
        "exim/config_active/exim_bP.txt" \
        "$EXIM_CMD -bP"
    
    # Config completa espansa (Debian con split config)
    if [ "$EXIM_CMD" = "exim4" ] && [ -x /usr/sbin/update-exim4.conf ]; then
        collect_cmd "Exim4 config espansa" \
            "exim/config_active/exim4_expanded.txt" \
            "$EXIM_CMD -bP config_file && cat \$($EXIM_CMD -bP config_file 2>/dev/null)"
    fi
    
    # TLS
    collect_cmd "Exim TLS settings" \
        "exim/config_active/tls_config.txt" \
        "$EXIM_CMD -bP tls_advertise_hosts tls_certificate tls_privatekey tls_require_ciphers"
    
    # Coda
    collect_cmd "Exim stato coda" \
        "exim/queue_status.txt" \
        "$EXIM_CMD -bp"
    
    echo "Exim: OK" >> "$SUMMARY"
fi

#############################################
# DOVECOT
#############################################

if [ "$MDA_FOUND" = "dovecot" ]; then
    log_info "=== Raccolta Dovecot ==="
    
    mkdir -p "$OUTDIR/dovecot/config_files"
    mkdir -p "$OUTDIR/dovecot/config_active"
    
    # Versione
    collect_cmd "Dovecot versione" "dovecot/version.txt" dovecot --version
    
    # File di configurazione
    for confdir in /etc/dovecot; do
        if [ -d "$confdir" ]; then
            # Copia struttura preservando path
            find "$confdir" -name "*.conf" -o -name "*.conf.ext" 2>/dev/null | while read -r f; do
                destfile="$OUTDIR/dovecot/config_files/${f#/etc/dovecot/}"
                mkdir -p "$(dirname "$destfile")"
                cp "$f" "$destfile" 2>/dev/null
            done
            log_info "Raccolti file config Dovecot"
        fi
    done
    
    # Configurazione attiva - password nascoste (sicuro per audit)
    collect_cmd "Dovecot config completa (password nascoste)" \
        "dovecot/config_active/doveconf_P.txt" \
        doveconf -P
    
    # Solo non-default per quick reference
    collect_cmd "Dovecot config non-default" \
        "dovecot/config_active/doveconf_n.txt" \
        doveconf -n
    
    # Non-default con plugin settings
    collect_cmd "Dovecot config con plugin" \
        "dovecot/config_active/doveconf_N.txt" \
        doveconf -N
    
    # Protocolli e listener
    collect_cmd "Dovecot protocolli" \
        "dovecot/config_active/protocols.txt" \
        "doveconf protocols"
    
    collect_cmd "Dovecot listeners" \
        "dovecot/config_active/listeners.txt" \
        "doveconf | grep -A5 'inet_listener\|unix_listener'"
    
    # SSL/TLS
    collect_cmd "Dovecot SSL config" \
        "dovecot/config_active/ssl_config.txt" \
        "doveconf | grep -i '^ssl'"
    
    # Auth
    collect_cmd "Dovecot auth config" \
        "dovecot/config_active/auth_config.txt" \
        "doveconf -n | grep -i auth"
    
    # Errori configurazione
    doveconf -n >/dev/null 2>"$OUTDIR/dovecot/config_errors.txt"
    if [ -s "$OUTDIR/dovecot/config_errors.txt" ]; then
        log_warn "Trovati warning/errori config Dovecot"
    else
        rm -f "$OUTDIR/dovecot/config_errors.txt"
    fi
    
    echo "Dovecot: OK" >> "$SUMMARY"
fi

#############################################
# CYRUS
#############################################

if [ "$MDA_FOUND" = "cyrus" ]; then
    log_info "=== Raccolta Cyrus ==="
    
    mkdir -p "$OUTDIR/cyrus/config_files"
    
    # File di configurazione
    for f in /etc/imapd.conf /etc/cyrus.conf; do
        [ -f "$f" ] && cp "$f" "$OUTDIR/cyrus/config_files/"
    done
    
    # Directory config aggiuntive
    for confdir in /etc/cyrus /etc/cyrus-imapd; do
        if [ -d "$confdir" ]; then
            cp -a "$confdir"/* "$OUTDIR/cyrus/config_files/" 2>/dev/null
        fi
    done
    
    log_info "Raccolti file config Cyrus"
    
    # Cyrus non ha equivalente di doveconf -n
    # Versione se disponibile
    if command -v imapd >/dev/null 2>&1; then
        collect_cmd "Cyrus versione" "cyrus/version.txt" "imapd -V"
    fi
    
    echo "Cyrus: OK (nota: no config attiva dinamica)" >> "$SUMMARY"
fi

#############################################
# FAIL2BAN (se presente)
#############################################

if command -v fail2ban-client >/dev/null 2>&1; then
    log_info "=== Raccolta Fail2ban ==="
    
    mkdir -p "$OUTDIR/fail2ban/config_files"
    mkdir -p "$OUTDIR/fail2ban/config_active"
    
    # File config
    for f in /etc/fail2ban/fail2ban.conf \
             /etc/fail2ban/jail.conf \
             /etc/fail2ban/jail.local \
             /etc/fail2ban/jail.d/*.conf \
             /etc/fail2ban/jail.d/*.local; do
        [ -f "$f" ] && cp "$f" "$OUTDIR/fail2ban/config_files/" 2>/dev/null
    done
    
    # Filtri relativi a mail
    for f in /etc/fail2ban/filter.d/dovecot*.conf \
             /etc/fail2ban/filter.d/postfix*.conf \
             /etc/fail2ban/filter.d/exim*.conf \
             /etc/fail2ban/filter.d/cyrus*.conf \
             /etc/fail2ban/filter.d/sasl*.conf; do
        [ -f "$f" ] && cp "$f" "$OUTDIR/fail2ban/config_files/" 2>/dev/null
    done
    
    log_info "Raccolti file config Fail2ban"
    
    # Stato attivo
    collect_cmd "Fail2ban stato generale" \
        "fail2ban/config_active/status.txt" \
        "fail2ban-client status"
    
    # Stato jail specifiche mail
    for jail in dovecot postfix postfix-sasl exim exim-spam cyrus-imap; do
        fail2ban-client status "$jail" >/dev/null 2>&1 && \
        collect_cmd "Fail2ban jail $jail" \
            "fail2ban/config_active/jail_${jail}.txt" \
            "fail2ban-client status $jail"
    done
    
    # IP attualmente bannati
    collect_cmd "Fail2ban IP bannati" \
        "fail2ban/config_active/banned_ips.txt" \
        "fail2ban-client banned"
    
    echo "Fail2ban: OK" >> "$SUMMARY"
else
    log_warn "Fail2ban non rilevato"
    echo "Fail2ban: NON INSTALLATO" >> "$SUMMARY"
fi

#############################################
# FIREWALL (regole relative a porte mail)
#############################################

log_info "=== Raccolta regole firewall ==="

mkdir -p "$OUTDIR/firewall"

# Rileva quale sistema è attivo
FW_TYPE="none"

if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
    FW_TYPE="nftables"
elif command -v iptables >/dev/null 2>&1 && iptables -L -n 2>/dev/null | grep -qv "^$"; then
    FW_TYPE="iptables"
fi

# Firewalld può coesistere come frontend
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
    if [ "$FW_TYPE" = "none" ]; then
        FW_TYPE="firewalld"
    else
        FW_TYPE="firewalld+$FW_TYPE"
    fi
fi

echo "firewall_type: $FW_TYPE" > "$OUTDIR/firewall/type.txt"
log_info "Firewall rilevato: $FW_TYPE"

# nftables
if command -v nft >/dev/null 2>&1; then
    {
        echo "# nft list ruleset (filtrato porte mail)"
        echo "# Porte: $MAIL_PORTS"
        echo "# ---"
        nft list ruleset 2>/dev/null | grep -E "dport\s+\{?($MAIL_PORTS)|sport\s+\{?($MAIL_PORTS)" || echo "# Nessuna regola specifica per porte mail trovata"
    } > "$OUTDIR/firewall/nftables_mail.txt"
    
    # Ruleset completo per contesto
    collect_cmd "nftables ruleset completo" \
        "firewall/nftables_full.txt" \
        "nft list ruleset"
fi

# iptables (anche se nftables è attivo, potrebbe esserci iptables-legacy)
if command -v iptables >/dev/null 2>&1; then
    {
        echo "# iptables -L -n -v (filtrato porte mail)"
        echo "# Porte: $MAIL_PORTS"
        echo "# ---"
        iptables -L -n -v 2>/dev/null | grep -E "dpt:($MAIL_PORTS)|spt:($MAIL_PORTS)" || echo "# Nessuna regola specifica per porte mail"
        echo ""
        echo "# === NAT table ==="
        iptables -t nat -L -n -v 2>/dev/null | grep -E "dpt:($MAIL_PORTS)|spt:($MAIL_PORTS)" || echo "# Nessuna regola NAT per porte mail"
    } > "$OUTDIR/firewall/iptables_mail.txt"
    
    collect_cmd "iptables completo" \
        "firewall/iptables_full.txt" \
        "iptables -L -n -v && echo '' && echo '=== NAT ===' && iptables -t nat -L -n -v"
    
    # Verifica se è iptables-nft o legacy
    if iptables -V 2>/dev/null | grep -q nf_tables; then
        echo "iptables_backend: nf_tables" >> "$OUTDIR/firewall/type.txt"
    else
        echo "iptables_backend: legacy" >> "$OUTDIR/firewall/type.txt"
    fi
fi

# ip6tables
if command -v ip6tables >/dev/null 2>&1; then
    {
        echo "# ip6tables -L -n -v (filtrato porte mail)"
        echo "# ---"
        ip6tables -L -n -v 2>/dev/null | grep -E "dpt:($MAIL_PORTS)|spt:($MAIL_PORTS)" || echo "# Nessuna regola IPv6 per porte mail"
    } > "$OUTDIR/firewall/ip6tables_mail.txt"
fi

# firewalld
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
    collect_cmd "firewalld zone attive" \
        "firewall/firewalld_zones.txt" \
        "firewall-cmd --list-all-zones"
    
    # Servizi mail abilitati per zona
    {
        echo "# Servizi mail in firewalld"
        echo "# Data: $(date -Is)"
        echo "# ---"
        
        # Ottieni zone attive
        firewall-cmd --get-active-zones 2>/dev/null | grep -v "^\s" | while read -r zone; do
            echo ""
            echo "## Zona: $zone"
            for svc in smtp smtps smtp-submission imap imaps pop3 pop3s managesieve; do
                if firewall-cmd --zone="$zone" --query-service="$svc" 2>/dev/null; then
                    echo "  $svc: ENABLED"
                else
                    echo "  $svc: disabled"
                fi
            done
            
            # Porte custom aperte
            echo "  Porte custom:"
            firewall-cmd --zone="$zone" --list-ports 2>/dev/null | tr ' ' '\n' | grep -E "^($MAIL_PORTS)/" | sed 's/^/    /'
        done
    } > "$OUTDIR/firewall/firewalld_mail_services.txt"
fi

echo "Firewall: $FW_TYPE" >> "$SUMMARY"

#############################################
# CERTIFICATI TLS
#############################################

log_info "=== Raccolta info certificati TLS ==="

mkdir -p "$OUTDIR/tls"

# Cerca certificati referenziati nelle config
CERT_FILES=""

# Da Postfix
if [ "$MTA_FOUND" = "postfix" ]; then
    CERT_FILES="$CERT_FILES $(postconf -h smtpd_tls_cert_file 2>/dev/null)"
    CERT_FILES="$CERT_FILES $(postconf -h smtpd_tls_chain_files 2>/dev/null)"
fi

# Da Exim
if [ "$MTA_FOUND" = "exim" ]; then
    EXIM_CMD="exim"
    command -v exim4 >/dev/null 2>&1 && EXIM_CMD="exim4"
    CERT_FILES="$CERT_FILES $($EXIM_CMD -bP tls_certificate 2>/dev/null | awk '{print $3}')"
fi

# Da Dovecot
if [ "$MDA_FOUND" = "dovecot" ]; then
    CERT_FILES="$CERT_FILES $(doveconf -h ssl_cert 2>/dev/null | tr -d '<')"
fi

# Analizza certificati (solo info, non chiavi private!)
for cert in $CERT_FILES; do
    if [ -f "$cert" ]; then
        certname=$(basename "$cert")
        {
            echo "# File: $cert"
            echo "# Data analisi: $(date -Is)"
            echo "# ---"
            openssl x509 -in "$cert" -noout -subject -issuer -dates -fingerprint -serial 2>/dev/null
            echo ""
            echo "# SAN (Subject Alternative Names):"
            openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null
        } > "$OUTDIR/tls/${certname}_info.txt"
        log_info "Analizzato certificato: $cert"
    fi
done

#############################################
# SERVIZI E PORTE
#############################################

log_info "=== Stato servizi e porte ==="

mkdir -p "$OUTDIR/system"

# Servizi attivi
if command -v systemctl >/dev/null 2>&1; then
    collect_cmd "Servizi mail attivi (systemd)" \
        "system/services.txt" \
        "systemctl list-units --type=service --state=running | grep -iE 'postfix|exim|dovecot|cyrus|fail2ban'"
else
    collect_cmd "Servizi mail attivi (init)" \
        "system/services.txt" \
        "service --status-all 2>/dev/null | grep -iE 'postfix|exim|dovecot|cyrus|fail2ban'"
fi

# Porte in ascolto (mail-related)
collect_cmd "Porte mail in ascolto" \
    "system/listening_ports.txt" \
    "ss -tlnp | grep -E ':($MAIL_PORTS)\s'"

# Alternativa con netstat se ss non disponibile
if [ ! -s "$OUTDIR/system/listening_ports.txt" ] && command -v netstat >/dev/null 2>&1; then
    collect_cmd "Porte mail in ascolto (netstat)" \
        "system/listening_ports.txt" \
        "netstat -tlnp | grep -E ':($MAIL_PORTS)\s'"
fi

#############################################
# TIMESTAMP PER ANALISI COERENZA
#############################################

log_info "=== Raccolta timestamp per coerenza config/servizio ==="

mkdir -p "$OUTDIR/timestamps"

{
    echo "# Timestamp per analisi coerenza configurazione vs servizio"
    echo "# Data raccolta: $(date -Is)"
    echo "# Epoch raccolta: $(date +%s)"
    echo "#"
    echo "# Se mtime_config > service_start => configurazione modificata ma servizio non riavviato"
    echo "# ---"
    echo ""
    
    # Postfix
    if [ "$MTA_FOUND" = "postfix" ]; then
        echo "## POSTFIX"
        if command -v systemctl >/dev/null 2>&1; then
            start_ts=$(systemctl show postfix --property=ActiveEnterTimestamp --value 2>/dev/null)
            echo "service_start_human: $start_ts"
            # Converti in epoch se possibile
            if [ -n "$start_ts" ] && [ "$start_ts" != "" ]; then
                start_epoch=$(date -d "$start_ts" +%s 2>/dev/null || echo "N/A")
                echo "service_start_epoch: $start_epoch"
            fi
        fi
        
        for cf in /etc/postfix/main.cf /etc/postfix/master.cf; do
            if [ -f "$cf" ]; then
                mtime=$(stat -c %Y "$cf" 2>/dev/null)
                mtime_human=$(stat -c %y "$cf" 2>/dev/null)
                echo "${cf}_mtime_epoch: $mtime"
                echo "${cf}_mtime_human: $mtime_human"
            fi
        done
        echo ""
    fi
    
    # Exim
    if [ "$MTA_FOUND" = "exim" ]; then
        echo "## EXIM"
        if command -v systemctl >/dev/null 2>&1; then
            # Trova il servizio exim (può essere exim4, exim, ecc.)
            svc=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -oE 'exim[0-9]*\.service' | head -1)
            if [ -n "$svc" ]; then
                start_ts=$(systemctl show "$svc" --property=ActiveEnterTimestamp --value 2>/dev/null)
                echo "service_name: $svc"
                echo "service_start_human: $start_ts"
                if [ -n "$start_ts" ] && [ "$start_ts" != "" ]; then
                    start_epoch=$(date -d "$start_ts" +%s 2>/dev/null || echo "N/A")
                    echo "service_start_epoch: $start_epoch"
                fi
            fi
        fi
        
        for cf in /etc/exim4/exim4.conf.template /etc/exim4/update-exim4.conf.conf /etc/exim/exim.conf; do
            if [ -f "$cf" ]; then
                mtime=$(stat -c %Y "$cf" 2>/dev/null)
                mtime_human=$(stat -c %y "$cf" 2>/dev/null)
                echo "${cf}_mtime_epoch: $mtime"
                echo "${cf}_mtime_human: $mtime_human"
            fi
        done
        echo ""
    fi
    
    # Dovecot
    if [ "$MDA_FOUND" = "dovecot" ]; then
        echo "## DOVECOT"
        if command -v systemctl >/dev/null 2>&1; then
            start_ts=$(systemctl show dovecot --property=ActiveEnterTimestamp --value 2>/dev/null)
            echo "service_start_human: $start_ts"
            if [ -n "$start_ts" ] && [ "$start_ts" != "" ]; then
                start_epoch=$(date -d "$start_ts" +%s 2>/dev/null || echo "N/A")
                echo "service_start_epoch: $start_epoch"
            fi
        fi
        
        # Trova il file più recente nella config Dovecot
        echo "# File configurazione e mtime:"
        find /etc/dovecot -type f \( -name "*.conf" -o -name "*.conf.ext" \) 2>/dev/null | while read -r cf; do
            mtime=$(stat -c %Y "$cf" 2>/dev/null)
            echo "${cf}_mtime_epoch: $mtime"
        done
        
        # Trova il più recente
        newest=$(find /etc/dovecot -type f \( -name "*.conf" -o -name "*.conf.ext" \) -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1)
        if [ -n "$newest" ]; then
            newest_file=$(echo "$newest" | awk '{print $2}')
            newest_mtime=$(echo "$newest" | awk '{print $1}' | cut -d. -f1)
            echo "newest_config_file: $newest_file"
            echo "newest_config_mtime_epoch: $newest_mtime"
        fi
        echo ""
    fi
    
    # Cyrus
    if [ "$MDA_FOUND" = "cyrus" ]; then
        echo "## CYRUS"
        if command -v systemctl >/dev/null 2>&1; then
            # Cerca servizio cyrus (può essere cyrus-imapd, cyrus-master, ecc.)
            for svc_name in cyrus-imapd cyrus-master cyrus; do
                if systemctl is-active "$svc_name" >/dev/null 2>&1; then
                    start_ts=$(systemctl show "$svc_name" --property=ActiveEnterTimestamp --value 2>/dev/null)
                    echo "service_name: $svc_name"
                    echo "service_start_human: $start_ts"
                    if [ -n "$start_ts" ] && [ "$start_ts" != "" ]; then
                        start_epoch=$(date -d "$start_ts" +%s 2>/dev/null || echo "N/A")
                        echo "service_start_epoch: $start_epoch"
                    fi
                    break
                fi
            done
        fi
        
        for cf in /etc/imapd.conf /etc/cyrus.conf; do
            if [ -f "$cf" ]; then
                mtime=$(stat -c %Y "$cf" 2>/dev/null)
                mtime_human=$(stat -c %y "$cf" 2>/dev/null)
                echo "${cf}_mtime_epoch: $mtime"
                echo "${cf}_mtime_human: $mtime_human"
            fi
        done
        echo ""
    fi
    
    # Fail2ban
    if command -v fail2ban-client >/dev/null 2>&1; then
        echo "## FAIL2BAN"
        if command -v systemctl >/dev/null 2>&1; then
            start_ts=$(systemctl show fail2ban --property=ActiveEnterTimestamp --value 2>/dev/null)
            echo "service_start_human: $start_ts"
            if [ -n "$start_ts" ] && [ "$start_ts" != "" ]; then
                start_epoch=$(date -d "$start_ts" +%s 2>/dev/null || echo "N/A")
                echo "service_start_epoch: $start_epoch"
            fi
        fi
        
        for cf in /etc/fail2ban/jail.local /etc/fail2ban/jail.conf /etc/fail2ban/fail2ban.conf; do
            if [ -f "$cf" ]; then
                mtime=$(stat -c %Y "$cf" 2>/dev/null)
                echo "${cf}_mtime_epoch: $mtime"
            fi
        done
        echo ""
    fi
    
} > "$OUTDIR/timestamps/service_vs_config.txt"

log_info "Timestamp servizi raccolti"

#############################################
# FINALIZZAZIONE
#############################################

# Riepilogo finale
{
    echo ""
    echo "==========================="
    echo "Raccolta completata"
    echo ""
    echo "File raccolti: $(find "$OUTDIR" -type f | wc -l)"
    echo "Dimensione totale: $(du -sh "$OUTDIR" | cut -f1)"
    echo ""
    echo "Struttura directory:"
    find "$OUTDIR" -type d | sed "s|$OUTDIR|.|" | sort
} >> "$SUMMARY"

# Crea archivio
ARCHIVE="${OUTDIR}.tar.gz"
tar czf "$ARCHIVE" "$OUTDIR" 2>/dev/null

log_info "=== Raccolta completata ==="
log_info "Directory: $OUTDIR"
log_info "Archivio: $ARCHIVE"
log_info "Riepilogo: $SUMMARY"

echo ""
cat "$SUMMARY"
