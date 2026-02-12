#!/bin/bash
#
# mailserver-audit-collect.sh
# Raccolta configurazioni mailserver per audit
# Supporta: Postfix, Exim (MTA) / Dovecot, Cyrus (MDA)
#
# Uso: sudo ./mailserver-audit-collect.sh
#

set -u

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
OUTDIR="mailaudit_${HOSTNAME}_${TIMESTAMP}"

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
    echo "Hostname: $HOSTNAME"
    echo "Data raccolta: $(date -Is)"
    echo "Utente: $(whoami)"
    echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
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
    
    if command -v "${1}" >/dev/null 2>&1; then
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
    
    # Configurazione attiva
    collect_cmd "Dovecot config attiva (non-default)" \
        "dovecot/config_active/doveconf_n.txt" \
        doveconf -n
    
    collect_cmd "Dovecot config completa" \
        "dovecot/config_active/doveconf_full.txt" \
        doveconf
    
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
        fail2ban-client status "$jail" >/dev/null 2>&1&& \
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
# CERTIFICATI TLS
#############################################

log_info "=== Raccolta info certificati TLS ==="

mkdir -p "$OUTDIR/tls"

# Cerca certificati referenziati nelle config
CERT_FILES=""

# Da Postfix
if [ "$MTA_FOUND" = "postfix" ]; then
    CERT_FILES="$CERT_FILES $(postconf -h smtpd_tls_cert_file 2>/dev/null)"
fi

# Da Dovecot
if [ "$MDA_FOUND" = "dovecot" ]; then
    CERT_FILES="$CERT_FILES $(doveconf -h ssl_cert 2>/dev/null | tr -d '<')"
fi

# Analizza certificati (solo info, non chiavi private!)
for cert in $CERT_FILES; do
    if [ -f "$cert" ]; then
        certname=$(basename "$cert")
        openssl x509 -in "$cert" -noout -subject -issuer -dates -fingerprint \
            > "$OUTDIR/tls/${certname}_info.txt" 2>/dev/null
        log_info "Analizzato certificato: $cert"
    fi
done

#############################################
# SERVIZI E PORTE
#############################################

log_info "=== Stato servizi e porte ==="

mkdir -p "$OUTDIR/system"

# Servizi attivi
collect_cmd "Servizi mail attivi" \
    "system/services.txt" \
    "systemctl list-units --type=service --state=running | grep -iE 'postfix|exim|dovecot|cyrus|fail2ban'"

# Porte in ascolto (mail-related)
collect_cmd "Porte mail in ascolto" \
    "system/listening_ports.txt" \
    "ss -tlnp | grep -E ':25|:465|:587|:110|:995|:143|:993|:4190'"


#############################################
# FINALIZZAZIONE
#############################################

# Riepilogo finale
{
    echo ""
    echo "==========================="
    echo "File raccolti:"
    find "$OUTDIR" -type f | wc -l
    echo ""
    echo "Dimensione totale:"
    du -sh "$OUTDIR"
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
