# mailserver-audit-collect

Scripts to collect configuration data from Linux mail servers for security audit purposes.

Each MTA has its own dedicated script (Postfix, Dovecot, Sendmail, Exim).

## Security guarantees

All scripts are strictly read-only:

- ✅ No modifications to system files or services
- ✅ No network calls outside the server (`curl`, `wget`, `nc` are never used)
- ✅ Only read operations via `cat`, `grep`, `awk`, and process inspection
- ✅ Output is a local `.tar.gz` archive containing collected data only

## Usage

```bash
sudo ./scripts/audit-postfix.sh
# Output: mailserver-audit-<hostname>-<date>.tar.gz
```
