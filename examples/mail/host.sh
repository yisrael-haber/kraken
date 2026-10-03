#!/bin/sh
# The host's end of the mail experiment, with standard servers:
#   sudo sh examples/mail/host.sh
# It runs Dovecot (POP3 on 192.168.122.1:110, IMAP on :143) with two messages for the user
# "test", password "secret", and aiosmtpd (SMTP on :25), which prints what it receives.
# Kraken's script is the client of all three; this waits until they have served it.
# Ports 25, 110 and 143 and Dovecot need root.
# Needs: sudo apt install dovecot-pop3d dovecot-imapd python3-aiosmtpd
set -e

HOST=192.168.122.1
DIR=/tmp/kraken-mail

if [ "$(id -u)" != 0 ]; then echo "run it with sudo: ports 25, 110 and 143 and Dovecot need root"; exit 1; fi
for tool in dovecot python3; do
    if ! command -v "$tool" > /dev/null; then echo "$tool not found: sudo apt install dovecot-pop3d dovecot-imapd python3-aiosmtpd"; exit 1; fi
done
if ! python3 -c "import aiosmtpd" 2> /dev/null; then echo "aiosmtpd not found: sudo apt install python3-aiosmtpd"; exit 1; fi

# The packages start their own Dovecot service, which holds the ports.
systemctl stop dovecot 2> /dev/null || true

rm -rf "$DIR"
mkdir -p "$DIR/mail/test/cur" "$DIR/mail/test/new" "$DIR/mail/test/tmp" "$DIR/home"
printf 'From: a@lab.test\r\nTo: test@lab.test\r\nSubject: First message\r\n\r\nthe first body\r\n' > "$DIR/mail/test/new/1.first"
printf 'From: b@lab.test\r\nTo: test@lab.test\r\nSubject: Second message\r\n\r\nthe second body\r\nand more\r\n' > "$DIR/mail/test/new/2.second"
echo 'test:{PLAIN}secret' > "$DIR/users"
chown -R nobody:nogroup "$DIR/mail" "$DIR/home"
cat > "$DIR/dovecot.conf" <<CONF
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0
base_dir = $DIR/run
state_dir = $DIR/state
log_path = /dev/stderr
listen = $HOST
ssl = no
auth_allow_cleartext = yes
auth_mechanisms = plain login
protocols {
  imap = yes
  pop3 = yes
}
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 0
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 0
  }
}
mail_driver = maildir
mail_path = $DIR/mail/%{user}
mail_home = $DIR/home/%{user}
namespace inbox {
  inbox = yes
}
passdb passwd-file {
  passwd_file_path = $DIR/users
}
userdb static {
  fields {
    uid = nobody
    gid = nogroup
  }
}
CONF

dovecot -F -c "$DIR/dovecot.conf" > "$DIR/dovecot.log" 2>&1 &
POP=$!
python3 -u -m aiosmtpd -n -l "$HOST:25" > "$DIR/smtp.log" 2>&1 &
SMTP=$!
trap 'kill $POP $SMTP 2> /dev/null' EXIT INT TERM

echo "Dovecot (POP3 on $HOST:110, IMAP on :143) and aiosmtpd (SMTP on $HOST:25); logs in $DIR"
echo "Run mail.lua in Kraken now."
until grep -q "END MESSAGE" "$DIR/smtp.log" && grep -q "pop3(test).*Logged out" "$DIR/dovecot.log" && grep -q "imap(test).*Logged out" "$DIR/dovecot.log"; do sleep 1; done
sleep 1
echo "--- the message aiosmtpd received:"
sed -n '/MESSAGE FOLLOWS/,/END MESSAGE/p' "$DIR/smtp.log"
echo "--- Dovecot's view of the POP3 and IMAP sessions:"
grep -E "pop3\(test\)|imap\(test\)|auth failed|Disconnected" "$DIR/dovecot.log" || true
echo "done; stopping Dovecot and aiosmtpd"
