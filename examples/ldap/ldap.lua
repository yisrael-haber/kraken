local identity = "base_192.168.122.5"
local host = "192.168.122.1"
local port = 3890
local tls_port = 6360
local base = "dc=example,dc=com"
local admin = "cn=admin," .. base
local password = "secret"
local timeout = 5000

local socket = require("kraken/socket")
local ldap = require("protocols/ldap")
local tls = require("protocols/tls")

local conn = ldap.connect(socket.tcp.connect(identity, host, port, timeout))

-- Anonymous, then a refused bind (the session stays usable), then the admin bind.
conn:bind("", "", timeout)
local ok, err = pcall(conn.bind, conn, admin, "wrong", timeout)
assert(not ok and err:find("Invalid credentials", 1, true), err)
conn:bind(admin, password, timeout)
assert(conn:extended("1.3.6.1.4.1.4203.1.11.3", nil, timeout) == "dn:" .. admin, "whoami")
print("bind: refused with a wrong password, accepted with the right one")

-- A non-admin user. The directory lets only bound users read ou=people, and nobody
-- but the admin write to it, so the bind decides what the session can see and do.
local alice_dn = "cn=alice,ou=people," .. base
local people_base = "ou=people," .. base
conn:bind("", "", timeout)
-- OpenLDAP hides entries an anonymous user may not read, so this is "No such object".
local found, hidden = pcall(conn.search, conn, { base = people_base, scope = "one" }, timeout)
assert(not found and hidden:find("No such object", 1, true) or found and #hidden == 0, "an anonymous session must not see people")
conn:bind(alice_dn, "alicepw", timeout)
assert(conn:extended("1.3.6.1.4.1.4203.1.11.3", nil, timeout) == "dn:" .. alice_dn, "whoami as alice")
assert(#conn:search({ base = people_base, scope = "one" }, timeout) == 2, "alice must see people")
local denied, reason = pcall(conn.add, conn, "cn=mallory," .. people_base, { objectClass = "inetOrgPerson", cn = "mallory", sn = "M" }, timeout)
assert(not denied and reason:find("Insufficient access", 1, true), reason)
local rejected, message = pcall(conn.bind, conn, alice_dn, "wrong", timeout)
assert(not rejected and message:find("Invalid credentials", 1, true), message)
conn:bind(admin, password, timeout)
print("auth: anonymous sees nothing, alice reads but cannot write, a wrong password is refused")

-- Search: scope, filter, requested attributes, a missing base.
local people = conn:search({ base = "ou=people," .. base, scope = "one", attributes = { "cn", "mail" } }, timeout)
assert(#people == 2, "expected the two seeded people, got " .. #people)
local alice
for _, entry in ipairs(people) do
    if entry.attributes.cn[1] == "alice" then alice = entry end
end
assert(alice and #alice.attributes.mail == 2 and alice.attributes.sn == nil)
assert(conn:search({ base = alice.dn, scope = "base" }, timeout)[1].attributes.sn[1] == "Anderson")
assert(#conn:search({ base = base, filter = "(cn=nobody)" }, timeout) == 0)
assert(not pcall(conn.search, conn, { base = "dc=missing", scope = "base" }, timeout))
print("search: " .. #people .. " people, alice has " .. #alice.attributes.mail .. " mail values")

-- Change entries: add, compare, modify, rename, delete.
local dn = "cn=carol,ou=people," .. base
conn:add(dn, { objectClass = "inetOrgPerson", cn = "carol", sn = "Clark", mail = "c@example.com" }, timeout)
assert(conn:compare(dn, "sn", "Clark", timeout) == true and conn:compare(dn, "sn", "Other", timeout) == false)
conn:modify(dn, {
    { op = "replace", attribute = "sn", values = "Clarke" },
    { op = "add", attribute = "mail", values = "carol@example.com" },
    { op = "delete", attribute = "mail", values = "c@example.com" },
}, timeout)
local carol = conn:search({ base = dn, scope = "base" }, timeout)[1]
assert(carol.attributes.sn[1] == "Clarke" and #carol.attributes.mail == 1)
conn:rename(dn, "cn=caroline", { parent = base }, timeout)
assert(#conn:search({ base = "cn=caroline," .. base, scope = "base" }, timeout) == 1)
conn:delete("cn=caroline," .. base, timeout)
assert(not pcall(conn.delete, conn, "cn=caroline," .. base, timeout), "second delete should fail")
print("modify: add, compare, modify, rename and delete all took effect")

-- A 100 KB value and 150 entries arrive in many TCP segments.
local big = string.rep("0123456789abcdef", 6400)
conn:add("cn=big," .. people_base, { objectClass = "inetOrgPerson", cn = "big", sn = "Big", description = big }, timeout)
assert(conn:search({ base = "cn=big," .. people_base, scope = "base" }, timeout)[1].attributes.description[1] == big)
for i = 1, 150 do
    conn:add("cn=bulk" .. i .. "," .. people_base, { objectClass = "inetOrgPerson", cn = "bulk" .. i, sn = "Bulk" }, timeout)
end
assert(#conn:search({ base = people_base, filter = "(cn=bulk*)" }, timeout) == 150)
assert(#conn:search({ base = people_base, filter = "(cn=bulk*)", limit = 10 }, timeout) == 10)
for i = 1, 150 do conn:delete("cn=bulk" .. i .. "," .. people_base, timeout) end
conn:delete("cn=big," .. people_base, timeout)
print("scale: a 100 KB value and 150 entries")

-- LDAPS: the same client over a TLS session, verified against the lab certificate
-- (CN and SAN kraken.test) that the server is started with.
local certificate = [[
-----BEGIN CERTIFICATE-----
MIIBmDCCAT+gAwIBAgIUTCWRjKS3mXjBRYwU3b9YSIvwSgUwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLa3Jha2VuLnRlc3QwHhcNMjYwOTI1MTQxNzI0WhcNMzYwOTIy
MTQxNzI0WjAWMRQwEgYDVQQDDAtrcmFrZW4udGVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABAlPuxWAKkTzOmeYh+275W+8PcSUJ7gyzLofa8tYaHJqQvh0qXO2
vy5kgYfY8PqajbaGBlQCdnPv303/SrJvZT+jazBpMB0GA1UdDgQWBBT/+CXb9dus
c56X1ZX97xVEB/9M5TAfBgNVHSMEGDAWgBT/+CXb9dusc56X1ZX97xVEB/9M5TAP
BgNVHRMBAf8EBTADAQH/MBYGA1UdEQQPMA2CC2tyYWtlbi50ZXN0MAoGCCqGSM49
BAMCA0cAMEQCIDDsS4CI+1L6ODhUgCSvYtepBKAYLB/sz5euDgLBOtOzAiA+lKsX
fbL4lsjrI6stxuqWVOp1QFw/cnqDvIjnyyKOng==
-----END CERTIFICATE-----
]]
local secure = ldap.connect(tls.connect(socket.tcp.connect(identity, host, tls_port, timeout), {
    server_name = "kraken.test", verify = true, ca = certificate,
}, timeout))
secure:bind(alice_dn, "alicepw", timeout)
assert(secure:extended("1.3.6.1.4.1.4203.1.11.3", nil, timeout) == "dn:" .. alice_dn, "whoami over LDAPS")
assert(#secure:search({ base = people_base, scope = "one" }, timeout) == 2, "alice must see people over LDAPS")
assert(not pcall(secure.add, secure, "cn=mallory," .. people_base, { objectClass = "inetOrgPerson", cn = "mallory", sn = "M" }, timeout))
secure:close()
print("ldaps: bind, who am I, search and a refused write over TLS")

conn:close()
print("ldap experiment passed")
