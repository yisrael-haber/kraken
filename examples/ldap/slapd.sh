#!/bin/sh
# A throwaway OpenLDAP server for the LDAP experiment. It runs in the foreground and
# prints every connection and operation; press Ctrl+C to stop it.
set -e

HOST=192.168.122.1
PORT=3890
TLS_PORT=6360
DIR=/tmp/kraken-ldap
CERT_DIR=$(cd "$(dirname "$0")/../../src/protocols/testdata" && pwd)
SLAPD=$(command -v slapd || echo /usr/sbin/slapd)
SLAPADD=$(command -v slapadd || echo /usr/sbin/slapadd)

SCHEMA=
for dir in /etc/ldap/schema /etc/openldap/schema /usr/share/openldap/schema; do
    if [ -f "$dir/core.schema" ]; then SCHEMA=$dir; break; fi
done
if [ -z "$SCHEMA" ]; then echo "OpenLDAP schema files not found: install slapd first"; exit 1; fi

# Debian and Fedora build the mdb backend as a loadable module; other builds have it in.
MODULES=
MODULE_DIR=
for dir in /usr/lib/ldap /usr/lib64/openldap /usr/lib/openldap /usr/libexec/openldap; do
    if [ -f "$dir/back_mdb.so" ]; then
        MODULE_DIR=$dir
        MODULES="modulepath $dir
moduleload back_mdb"
        break
    fi
done

rm -rf "$DIR"
mkdir -p "$DIR/db"
# The lab certificate (CN and SAN kraken.test) that the HTTPS experiment uses, for LDAPS.
cp "$CERT_DIR/lab_cert.pem" "$CERT_DIR/lab_key.pem" "$DIR/"
chmod 600 "$DIR/lab_key.pem"

cat > "$DIR/slapd.conf" <<CONF
$MODULES
include $SCHEMA/core.schema
include $SCHEMA/cosine.schema
include $SCHEMA/inetorgperson.schema
TLSCertificateFile $DIR/lab_cert.pem
TLSCertificateKeyFile $DIR/lab_key.pem
database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory $DIR/db
maxsize 104857600
index objectClass eq
access to attrs=userPassword by anonymous auth by self write by * none
access to dn.subtree="ou=people,dc=example,dc=com" by users read by * none
access to * by * read
CONF

cat > "$DIR/seed.ldif" <<LDIF
dn: dc=example,dc=com
objectClass: top
objectClass: dcObject
objectClass: organization
o: Example
dc: example

dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: cn=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
cn: alice
sn: Anderson
mail: alice@example.com
mail: a@example.com
userPassword: alicepw

dn: cn=bob,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
cn: bob
sn: Brown
mail: bob@example.com
LDIF

"$SLAPADD" -f "$DIR/slapd.conf" -l "$DIR/seed.ldif"
echo "LDAP on ldap://$HOST:$PORT and LDAPS on ldaps://$HOST:$TLS_PORT  (admin cn=admin,dc=example,dc=com / secret; user cn=alice,ou=people,dc=example,dc=com / alicepw)"
exec "$SLAPD" -f "$DIR/slapd.conf" -h "ldap://$HOST:$PORT ldaps://$HOST:$TLS_PORT" -d 256
