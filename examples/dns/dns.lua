local identity = "base_192.168.122.5"
local address = "192.168.122.5"
local host = "192.168.122.1"

local dns = require("protocols/dns")
local socket = require("kraken/socket")
local types = dns.types

-- Client: ask the host's resolver (libvirt's dnsmasq) for example.com.
local client = socket.udp.connect(identity, host, 53)
client:send(dns.encode({
    id = 0x4b52,
    flags = { rd = true },
    questions = { { name = "example.com", type = types.A } },
}), 5000)
local reply = dns.decode((client:receive(5000)))
client:close()
assert(reply.id == 0x4b52 and reply.flags.qr and #reply.questions == 1)
assert(reply.questions[1].name:lower() == "example.com" and reply.questions[1].type == types.A)
print("client: rcode " .. reply.rcode .. ", " .. #reply.answers .. " answer(s)")
for _, record in ipairs(reply.answers) do
    print("client:", record.name, record.type, record.ttl, record.addr or record.cname or "")
end

-- Server: answer one query from the host.
local server = socket.udp.bind(identity, address, 10053)
print("server: waiting for a query on " .. address .. ":10053")
local bytes, peer, port = server:receive(120000)
local query = dns.decode(bytes)
local question = query.questions[1]
assert(question and question.name:lower() == "kraken.test", "expected a query for kraken.test")
local answers = {}
if question.type == types.A then
    answers[1] = { name = question.name, type = types.A, ttl = 60, addr = "192.0.2.53" }
elseif question.type == types.TXT then
    answers[1] = { name = question.name, type = types.TXT, ttl = 60, data = { "hello from kraken" } }
end
server:send(dns.encode({
    id = query.id,
    flags = { qr = true, aa = true, rd = query.flags.rd },
    questions = query.questions,
    answers = answers,
}), peer, port, 5000)
server:close()
print("server: answered " .. peer .. " (type " .. question.type .. ")")

print("dns experiment passed")
