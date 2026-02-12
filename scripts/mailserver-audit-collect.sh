#!/bin/bash
#
# mailserver-audit-collect.sh
# Raccolta configurazioni mailserver per audit
# Supporta: Postfix, Exim (MTA) / Dovecot, Cyrus (MDA)
#
# Versione: 2.2
# Uso: sudo ./mailserver-audit-collect.sh
#
# Modifiche v2.2:
# - Gestione log ruotati e compressi (.gz, .bz2, .xz)
# - Funzione read_rotated_logs() per concatenare log in ordine cronologico
# - Aumentato sample size (20→30 per top IP, 10→20 per eventi)
# - Aggiunta distribuzione temporale attacchi per giorno
#
# Modifiche v2.1:
# - Aggiunta verifica partizioni mail (/var/mail, /var/spool, ecc.)
# - Aggiunta raccolta package info per valutazione CVE
# - Aggiunto dovecot --build-options per CVE specifiche moduli
# - Aggiunta sezione analisi log (statistiche eventi critici)
# - Aggiunta raccolta top IP per auth failure
#
# Modifiche v2.0:
# - Aggiunto doveconf -P (password nascoste) e -N (include plugin)
# - Aggiunta raccolta regole firewall (iptables, nftables, firewalld)
# - Aggiunta raccolta timestamp per verifica coerenza config vs servizio
# - Rimossa sezione diff (eseguire lato auditor)
#

set -u

SCRIPT_VERSION="2.2"
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

# Funzione per leggere log ruotati (compressi e non)
# Uso: read_rotated_logs /var/log/maillog | grep 'pattern'
# Gestisce: .gz, .bz2, .xz e file non compressi
# Ordine: dal più vecchio al più recente
read_rotated_logs() {
    local base="$1"
    local max_files="${2:-10}"  # Default: ultimi 10 file (incluso attivo)
    local files_found=""
    
    # Trova tutti i file correlati
    # Pattern: base, base.0, base.1, base.N, base.N.gz, base.N.bz2, base.N.xz
    for f in "${base}".[0-9]* "${base}".[0-9]*.gz "${base}".[0-9]*.bz2 "${base}".[0-9]*.xz \
             "${base}"-[0-9]* "${base}"-[0-9]*.gz "${base}"-[0-9]*.bz2 "${base}"-[0-9]*.xz; do
        [ -f "$f" ] && files_found="$files_found $f"
    done
    
    # Aggiungi file base se esiste
    [ -f "$base" ] && files_found="$files_found $base"
    
    # Ordina per data modifica (più vecchio prima) e limita
    # shellcheck disable=SC2086
    local sorted_files
    sorted_files=$(ls -1t $files_found 2>/dev/null | tail -n "$max_files" | tac)
    
    # Leggi ogni file con il tool appropriato
    for f in $sorted_files; do
        case "$f" in
            *.gz)
                if command -v zcat >/dev/null 2>&1; then
                    zcat "$f" 2>/dev/null
                elif command -v gzip >/dev/null 2>&1; then
                    gzip -dc "$f" 2>/dev/null
                fi
                ;;
            *.bz2)
                if command -v bzcat >/dev/null 2>&1; then
                    bzcat "$f" 2>/dev/null
                elif command -v bzip2 >/dev/null 2>&1; then
                    bzip2 -dc "$f" 2>/dev/null
                fi
                ;;
            *.xz)
                if command -v xzcat >/dev/null 2>&1; then
                    xzcat "$f" 2>/dev/null
                elif command -v xz >/dev/null 2>&1; then
                    xz -dc "$f" 2>/dev/null
                fi
                ;;
            *)
                cat "$f" 2>/dev/null
                ;;
        esac
    done
}

# Funzione per trovare il file base del log mail
find_mail_log_base() {
    for logbase in /var/log/mail.log /var/log/maillog /var/log/mail/mail.log; do
        # Verifica se esiste il file base O file ruotati
        if [ -f "$logbase" ] || ls "${logbase}".[0-9]* >/dev/null 2>&1 || \
           ls "${logbase}"-[0-9]* >/dev/null 2>&1; then
            echo "$logbase"
            return 0
        fi
    done
    return 1
}

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
    
    # Pacchetto installato (per verificare backport security)
    {
        echo "# Informazioni pacchetto Postfix per valutazione CVE"
        echo "# Data: $(date -Is)"
        echo "# ---"
        echo ""
        
        # Debian/Ubuntu
        if command -v dpkg >/dev/null 2>&1; then
            echo "## dpkg info"
            dpkg -l | grep -i postfix 2>/dev/null
            echo ""
            echo "## apt policy"
            apt-cache policy postfix 2>/dev/null
        fi
        
        # RHEL/CentOS/Fedora
        if command -v rpm >/dev/null 2>&1; then
            echo "## rpm info"
            rpm -qa | grep -i postfix 2>/dev/null
            echo ""
            echo "## rpm details"
            rpm -qi postfix 2>/dev/null
        fi
    } > "$OUTDIR/postfix/package_info.txt"
    
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
    
    # Pacchetto installato (per verificare backport security)
    {
        echo "# Informazioni pacchetto Exim per valutazione CVE"
        echo "# Data: $(date -Is)"
        echo "# ---"
        echo ""
        
        # Debian/Ubuntu
        if command -v dpkg >/dev/null 2>&1; then
            echo "## dpkg info"
            dpkg -l | grep -i exim 2>/dev/null
            echo ""
            echo "## apt policy"
            apt-cache policy exim4-daemon-heavy 2>/dev/null || apt-cache policy exim4-daemon-light 2>/dev/null
        fi
        
        # RHEL/CentOS/Fedora
        if command -v rpm >/dev/null 2>&1; then
            echo "## rpm info"
            rpm -qa | grep -i exim 2>/dev/null
            echo ""
            echo "## rpm details"
            rpm -qi exim 2>/dev/null
        fi
    } > "$OUTDIR/exim/package_info.txt"
    
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
    
    # Versione e build info per valutazione CVE
    collect_cmd "Dovecot versione" "dovecot/version.txt" dovecot --version
    
    # Build options - importante per CVE (alcuni sono specifici per moduli)
    collect_cmd "Dovecot build options" "dovecot/build_options.txt" dovecot --build-options
    
    # Pacchetto installato (per verificare backport security)
    {
        echo "# Informazioni pacchetto Dovecot per valutazione CVE"
        echo "# Data: $(date -Is)"
        echo "# ---"
        echo ""
        
        # Debian/Ubuntu
        if command -v dpkg >/dev/null 2>&1; then
            echo "## dpkg info"
            dpkg -l | grep -i dovecot 2>/dev/null
            echo ""
            echo "## apt policy"
            apt-cache policy dovecot-core 2>/dev/null
        fi
        
        # RHEL/CentOS/Fedora
        if command -v rpm >/dev/null 2>&1; then
            echo "## rpm info"
            rpm -qa | grep -i dovecot 2>/dev/null
            echo ""
            echo "## rpm details"
            rpm -qi dovecot 2>/dev/null || rpm -qi dovecot-core 2>/dev/null
        fi
    } > "$OUTDIR/dovecot/package_info.txt"
    
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
# PARTIZIONI E STORAGE MAIL
#############################################

log_info "=== Verifica partizioni mail ==="

{
    echo "# Analisi partizioni per directory mail-critical"
    echo "# Data: $(date -Is)"
    echo "#"
    echo "# NOTA AUDIT: directory mail su partizione separata da root = buona pratica"
    echo "#             Protegge da DoS via riempimento disco"
    echo "# ---"
    echo ""
    
    # Identifica root device
    ROOT_DEV=$(df / 2>/dev/null | tail -1 | awk '{print $1}')
    echo "root_device: $ROOT_DEV"
    echo "root_mountpoint: /"
    echo ""
    
    # Directory mail-related da verificare
    MAIL_DIRS="/var/mail /var/vmail /var/spool/mail /var/spool/postfix /var/spool/exim /var/spool/exim4 /var/spool/cyrus /var/lib/dovecot /var/lib/cyrus"
    
    echo "## Verifica separazione partizioni"
    echo ""
    
    for dir in $MAIL_DIRS; do
        if [ -d "$dir" ]; then
            # Trova device e mountpoint per questa directory
            dir_info=$(df "$dir" 2>/dev/null | tail -1)
            dir_dev=$(echo "$dir_info" | awk '{print $1}')
            dir_mount=$(echo "$dir_info" | awk '{print $6}')
            dir_size=$(echo "$dir_info" | awk '{print $2}')
            dir_used=$(echo "$dir_info" | awk '{print $3}')
            dir_avail=$(echo "$dir_info" | awk '{print $4}')
            dir_pct=$(echo "$dir_info" | awk '{print $5}')
            
            # Verifica se è su partizione diversa da root
            if [ "$dir_dev" = "$ROOT_DEV" ]; then
                separation="NO (stessa partizione di root)"
            else
                separation="SI (partizione dedicata: $dir_mount)"
            fi
            
            echo "directory: $dir"
            echo "  device: $dir_dev"
            echo "  mountpoint: $dir_mount"
            echo "  separated_from_root: $separation"
            echo "  size_kb: $dir_size"
            echo "  used_kb: $dir_used"
            echo "  available_kb: $dir_avail"
            echo "  used_percent: $dir_pct"
            
            # Dimensione contenuto directory
            dir_du=$(du -sk "$dir" 2>/dev/null | awk '{print $1}')
            echo "  content_size_kb: $dir_du"
            echo ""
        fi
    done
    
    echo ""
    echo "## Riepilogo mount points rilevanti"
    echo ""
    df -h 2>/dev/null | grep -E '(/var/mail|/var/vmail|/var/spool|/home|/$)' | head -20
    
    echo ""
    echo "## Mount options (per verifica noexec, nosuid su mail dirs)"
    echo ""
    mount | grep -E '(/var/mail|/var/vmail|/var/spool|/home| / )' 2>/dev/null
    
    echo ""
    echo "## Quota filesystem (se attive)"
    echo ""
    if command -v repquota >/dev/null 2>&1; then
        repquota -a 2>/dev/null | head -30 || echo "# repquota non disponibile o nessuna quota attiva"
    else
        echo "# repquota non installato"
    fi
    
    # Verifica quota Dovecot (se configurato)
    if [ "$MDA_FOUND" = "dovecot" ]; then
        echo ""
        echo "## Dovecot quota plugin config"
        doveconf -n 2>/dev/null | grep -i quota || echo "# Nessuna configurazione quota in Dovecot"
    fi
    
} > "$OUTDIR/system/partitions_mail.txt"

log_info "Analisi partizioni completata"

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
# ANALISI LOG - STATISTICHE EVENTI CRITICI
#############################################

log_info "=== Analisi log eventi critici ==="

mkdir -p "$OUTDIR/logs"

# Trova base path dei log
MAIL_LOG_BASE=$(find_mail_log_base)

AUTH_LOG_BASE=""
for logbase in /var/log/auth.log /var/log/secure /var/log/auth/auth.log; do
    if [ -f "$logbase" ] || ls "${logbase}".[0-9]* >/dev/null 2>&1; then
        AUTH_LOG_BASE="$logbase"
        break
    fi
done

DOVECOT_LOG_BASE=""
for logbase in /var/log/dovecot.log /var/log/dovecot/dovecot.log; do
    if [ -f "$logbase" ] || ls "${logbase}".[0-9]* >/dev/null 2>&1; then
        DOVECOT_LOG_BASE="$logbase"
        break
    fi
done

# Parametro: quanti file ruotati processare (default 10 = circa 10-30 giorni tipicamente)
LOG_ROTATION_DEPTH=10

{
    echo "# Statistiche eventi critici dai log"
    echo "# Data analisi: $(date -Is)"
    echo "# Profondità rotazione: ultimi $LOG_ROTATION_DEPTH file (compressi inclusi)"
    echo "#"
    echo "# NOTA: Processa log ruotati (.gz, .bz2, .xz) in ordine cronologico"
    echo "# ---"
    echo ""
    
    if [ -n "$MAIL_LOG_BASE" ]; then
        echo "## Mail log base: $MAIL_LOG_BASE"
        
        # Elenca file trovati
        echo "### File processati:"
        for f in "${MAIL_LOG_BASE}".[0-9]* "${MAIL_LOG_BASE}".[0-9]*.gz \
                 "${MAIL_LOG_BASE}".[0-9]*.bz2 "${MAIL_LOG_BASE}".[0-9]*.xz \
                 "${MAIL_LOG_BASE}"-[0-9]* "${MAIL_LOG_BASE}"-[0-9]*.gz \
                 "${MAIL_LOG_BASE}"-[0-9]*.bz2 "${MAIL_LOG_BASE}"-[0-9]*.xz \
                 "${MAIL_LOG_BASE}"; do
            [ -f "$f" ] && ls -lh "$f" 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
        done
        echo ""
        
        # Conta righe totali processate
        total_lines=$(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | wc -l)
        echo "total_lines_processed: $total_lines"
        echo ""
        
        # Postfix events
        if [ "$MTA_FOUND" = "postfix" ]; then
            echo "### Postfix eventi"
            echo ""
            
            echo "reject_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'reject:' 2>/dev/null || echo 0)"
            echo "warning_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'warning:' 2>/dev/null || echo 0)"
            echo "error_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'error:' 2>/dev/null || echo 0)"
            echo "fatal_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'fatal:' 2>/dev/null || echo 0)"
            echo "timeout_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'timeout' 2>/dev/null || echo 0)"
            echo "relay_denied_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'Relay access denied' 2>/dev/null || echo 0)"
            echo "sasl_auth_failed_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'SASL.*authentication failed' 2>/dev/null || echo 0)"
            echo "tls_error_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'tls.*error\|ssl.*error' 2>/dev/null || echo 0)"
            echo ""
            
            echo "### Ultimi 20 reject (sample)"
            read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep 'reject:' | tail -20 | sed 's/^/  /'
            echo ""
            
            echo "### Ultimi 20 SASL auth failed (sample)"
            read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep 'SASL.*authentication failed' | tail -20 | sed 's/^/  /'
            echo ""
        fi
        
        # Exim events
        if [ "$MTA_FOUND" = "exim" ]; then
            echo "### Exim eventi"
            echo ""
            
            echo "rejected_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'rejected' 2>/dev/null || echo 0)"
            echo "refused_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'refused' 2>/dev/null || echo 0)"
            echo "error_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'error' 2>/dev/null || echo 0)"
            echo "timeout_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'timeout' 2>/dev/null || echo 0)"
            echo "auth_failed_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'authenticator failed' 2>/dev/null || echo 0)"
            echo "tls_error_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'tls.*error\|ssl.*error' 2>/dev/null || echo 0)"
            echo ""
            
            echo "### Ultimi 20 rejected (sample)"
            read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -i 'rejected\|refused' | tail -20 | sed 's/^/  /'
            echo ""
        fi
        
        # Dovecot events (spesso nello stesso log)
        if [ "$MDA_FOUND" = "dovecot" ]; then
            echo "### Dovecot eventi (da mail.log)"
            echo ""
            
            echo "auth_failed_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'dovecot.*auth failed\|dovecot.*authentication failure' 2>/dev/null || echo 0)"
            echo "login_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'dovecot.*Login' 2>/dev/null || echo 0)"
            echo "disconnect_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'dovecot.*Disconnected' 2>/dev/null || echo 0)"
            echo "error_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'dovecot.*Error\|dovecot.*error' 2>/dev/null || echo 0)"
            echo "warning_count: $(read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'dovecot.*Warning\|dovecot.*warning' 2>/dev/null || echo 0)"
            echo ""
        fi
    else
        echo "## Mail log: NON TROVATO"
        echo "# Cercati: /var/log/mail.log, /var/log/maillog, /var/log/mail/mail.log"
        echo "# (inclusi file ruotati .N, .N.gz, .N.bz2, .N.xz)"
        echo ""
    fi
    
    # Dovecot log separato (alcune configurazioni)
    if [ -n "$DOVECOT_LOG_BASE" ] && [ "$MDA_FOUND" = "dovecot" ]; then
        echo "## Dovecot log dedicato: $DOVECOT_LOG_BASE"
        
        # Elenca file
        echo "### File processati:"
        for f in "${DOVECOT_LOG_BASE}".[0-9]* "${DOVECOT_LOG_BASE}".[0-9]*.gz \
                 "${DOVECOT_LOG_BASE}".[0-9]*.bz2 "${DOVECOT_LOG_BASE}".[0-9]*.xz \
                 "${DOVECOT_LOG_BASE}"; do
            [ -f "$f" ] && ls -lh "$f" 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
        done
        echo ""
        
        echo "auth_failed_count: $(read_rotated_logs "$DOVECOT_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'auth failed\|authentication failure' 2>/dev/null || echo 0)"
        echo "login_count: $(read_rotated_logs "$DOVECOT_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'Login' 2>/dev/null || echo 0)"
        echo "error_count: $(read_rotated_logs "$DOVECOT_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'error' 2>/dev/null || echo 0)"
        echo "warning_count: $(read_rotated_logs "$DOVECOT_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -ci 'warning' 2>/dev/null || echo 0)"
        echo ""
        
        echo "### Ultimi 20 auth failed (sample)"
        read_rotated_logs "$DOVECOT_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -i 'auth failed\|authentication failure' | tail -20 | sed 's/^/  /'
        echo ""
        
        echo "### Ultimi 20 errori (sample)"
        read_rotated_logs "$DOVECOT_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -i 'error' | tail -20 | sed 's/^/  /'
        echo ""
    fi
    
    # Auth log per tentativi brute force
    if [ -n "$AUTH_LOG_BASE" ]; then
        echo "## Auth log: $AUTH_LOG_BASE"
        echo ""
        
        # Fail2ban bans (se presente)
        if command -v fail2ban-client >/dev/null 2>&1; then
            echo "### Fail2ban bans"
            echo "ban_count: $(read_rotated_logs "$AUTH_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'fail2ban.*Ban' 2>/dev/null || echo 0)"
            echo "unban_count: $(read_rotated_logs "$AUTH_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep -c 'fail2ban.*Unban' 2>/dev/null || echo 0)"
            echo ""
            
            echo "### Ultimi 20 ban (sample)"
            read_rotated_logs "$AUTH_LOG_BASE" "$LOG_ROTATION_DEPTH" | grep 'fail2ban.*Ban' | tail -20 | sed 's/^/  /'
            echo ""
        fi
    fi
    
    # Statistiche journalctl se disponibile (sistemi con systemd)
    if command -v journalctl >/dev/null 2>&1; then
        echo "## Statistiche journalctl (ultima settimana)"
        echo ""
        
        if [ "$MTA_FOUND" = "postfix" ]; then
            echo "### Postfix via journalctl"
            echo "total_entries: $(journalctl -u postfix --since '1 week ago' 2>/dev/null | wc -l)"
            echo "error_entries: $(journalctl -u postfix --since '1 week ago' -p err 2>/dev/null | wc -l)"
            echo "warning_entries: $(journalctl -u postfix --since '1 week ago' -p warning 2>/dev/null | wc -l)"
            echo ""
        fi
        
        if [ "$MDA_FOUND" = "dovecot" ]; then
            echo "### Dovecot via journalctl"
            echo "total_entries: $(journalctl -u dovecot --since '1 week ago' 2>/dev/null | wc -l)"
            echo "error_entries: $(journalctl -u dovecot --since '1 week ago' -p err 2>/dev/null | wc -l)"
            echo "warning_entries: $(journalctl -u dovecot --since '1 week ago' -p warning 2>/dev/null | wc -l)"
            echo ""
        fi
        
        if command -v fail2ban-client >/dev/null 2>&1; then
            echo "### Fail2ban via journalctl"
            echo "total_entries: $(journalctl -u fail2ban --since '1 week ago' 2>/dev/null | wc -l)"
            echo "ban_entries: $(journalctl -u fail2ban --since '1 week ago' 2>/dev/null | grep -c 'Ban')"
            echo ""
        fi
    fi
    
} > "$OUTDIR/logs/critical_events_stats.txt"

log_info "Statistiche log raccolte"

# Top IP per auth failure (utile per identificare attacchi)
{
    echo "# Top IP per autenticazioni fallite"
    echo "# Data: $(date -Is)"
    echo "# Profondità: ultimi $LOG_ROTATION_DEPTH file log (compressi inclusi)"
    echo "# ---"
    echo ""
    
    if [ -n "$MAIL_LOG_BASE" ]; then
        echo "## Da mail log ($MAIL_LOG_BASE + ruotati)"
        echo ""
        
        # Postfix SASL failures
        if [ "$MTA_FOUND" = "postfix" ]; then
            echo "### Top 30 IP - SASL auth failed"
            read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | \
                grep 'SASL.*authentication failed' | \
                grep -oE '\[([0-9]{1,3}\.){3}[0-9]{1,3}\]' | \
                tr -d '[]' | sort | uniq -c | sort -rn | head -30
            echo ""
        fi
        
        # Exim auth failures
        if [ "$MTA_FOUND" = "exim" ]; then
            echo "### Top 30 IP - Exim auth failed"
            read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | \
                grep -i 'authenticator failed\|AUTH.*failed' | \
                grep -oE '\[([0-9]{1,3}\.){3}[0-9]{1,3}\]' | \
                tr -d '[]' | sort | uniq -c | sort -rn | head -30
            echo ""
        fi
        
        # Dovecot auth failures (da mail log)
        if [ "$MDA_FOUND" = "dovecot" ]; then
            echo "### Top 30 IP - Dovecot auth failed"
            read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | \
                grep -i 'dovecot.*auth failed\|dovecot.*authentication failure' | \
                grep -oE 'rip=([0-9]{1,3}\.){3}[0-9]{1,3}' | \
                cut -d= -f2 | sort | uniq -c | sort -rn | head -30
            echo ""
        fi
    fi
    
    # Dovecot log dedicato
    if [ -n "$DOVECOT_LOG_BASE" ] && [ "$MDA_FOUND" = "dovecot" ]; then
        echo "## Da Dovecot log dedicato ($DOVECOT_LOG_BASE + ruotati)"
        echo "### Top 30 IP - auth failed"
        read_rotated_logs "$DOVECOT_LOG_BASE" "$LOG_ROTATION_DEPTH" | \
            grep -i 'auth failed\|authentication failure' | \
            grep -oE 'rip=([0-9]{1,3}\.){3}[0-9]{1,3}' | \
            cut -d= -f2 | sort | uniq -c | sort -rn | head -30
        echo ""
    fi
    
    # Distribuzione temporale attacchi (per giorno)
    echo "## Distribuzione auth failure per giorno"
    echo ""
    
    if [ -n "$MAIL_LOG_BASE" ]; then
        echo "### Da mail log"
        read_rotated_logs "$MAIL_LOG_BASE" "$LOG_ROTATION_DEPTH" | \
            grep -iE 'auth.*fail|authentication failure|SASL.*failed' | \
            grep -oE '^[A-Za-z]{3} [ 0-9]{2}' | sort | uniq -c | tail -30
        echo ""
    fi
    
} > "$OUTDIR/logs/top_failed_auth_ips.txt"

log_info "Top IP auth failure raccolti"

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
