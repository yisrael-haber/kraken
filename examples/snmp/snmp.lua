local identity = "base_192.168.122.5"
local address = "192.168.122.5"
local host = "192.168.122.1"
local agent_port = 161    -- snmpd on the host (host.sh)
local trap_port = 162     -- snmptrapd on the host
local own_port = 161      -- this script's agent, on Kraken's address
local timeout = 3000

local socket = require("kraken/socket")
local snmp = require("protocols/snmp")

local udp = socket.udp.bind(identity, address, 1612)
local request_id = 100

-- Manager: one request, and the response that carries its request id. Anything else that
-- arrives (a late answer to an earlier request) is skipped.
local function ask(message, wait)
    request_id = request_id + 1
    message.request_id = request_id
    udp:send(snmp.encode(message), host, agent_port, timeout)
    while true do
        local reply = snmp.decode((udp:receive(wait or timeout)))
        if reply.request_id == request_id then return reply end
    end
end

local function under(oid, root) return oid == root or oid:sub(1, #root + 1) == root .. "." end

-- A walk is a getnext loop that stops outside the subtree or at the end of the MIB.
local function walk(root)
    local found, current = {}, root
    while true do
        local reply = ask({ pdu = "getnext", varbinds = { { oid = current } } })
        local varbind = reply.varbinds[1]
        if not varbind or varbind.type == "end_of_mib_view" or not under(varbind.oid, root) then return found end
        found[#found + 1] = varbind
        current = varbind.oid
    end
end

-- get: typed values come back as Lua values. The values belong to the host's snmpd, so
-- this checks their types and relations, and sysName, which host.sh sets.
local reply = ask({ pdu = "get", varbinds = {
    { oid = "1.3.6.1.2.1.1.1.0" }, { oid = "1.3.6.1.2.1.1.2.0" }, { oid = "1.3.6.1.2.1.1.3.0" },
    { oid = "1.3.6.1.2.1.1.5.0" }, { oid = "1.3.6.1.2.1.2.1.0" }, { oid = "1.3.6.1.2.1.11.1.0" },
    { oid = "1.3.6.1.2.1.31.1.1.1.6.1" },
} })
local v = reply.varbinds
assert(reply.pdu == "response" and reply.error_status == 0 and #v == 7, "a get of seven objects")
assert(v[1].type == "octet_string" and #v[1].value > 0, "sysDescr")
assert(v[2].type == "oid" and v[2].value:find("^1%.3%.6%.1%."), "sysObjectID")
assert(v[3].type == "time_ticks" and v[3].value > 0, "sysUpTime")
assert(v[4].type == "octet_string" and v[4].value == "kraken-lab-host", "sysName")
assert(v[5].type == "integer" and v[5].value >= 1, "ifNumber")
assert(v[6].type == "counter32", "snmpInPkts")
assert(v[7].type == "counter64", "ifHCInOctets.1")
print("get: seven typed values (" .. v[1].value .. ")")

-- Errors differ by version: v2c answers with an exception value, v1 with an error status.
assert(ask({ pdu = "get", varbinds = { { oid = "1.3.6.1.9" } } }).varbinds[1].type == "no_such_object")
local old = ask({ version = "v1", pdu = "get", varbinds = { { oid = "1.3.6.1.9" } } })
assert(old.version == "v1" and old.error_status == 2 and old.error_index == 1)
local refused = ask({ pdu = "set", varbinds = { { oid = "1.3.6.1.2.1.1.5.0", value = "changed" } } })
assert(refused.error_status ~= 0, "a read-only community must not be able to set")
print("errors: noSuchObject (v2c), noSuchName (v1), and a refused set (error status " .. refused.error_status .. ")")

-- getnext, getbulk and walks.
assert(ask({ pdu = "getnext", varbinds = { { oid = "1.3.6.1.2.1.1.1.0" } } }).varbinds[1].oid == "1.3.6.1.2.1.1.2.0")
local bulk = ask({ pdu = "getbulk", non_repeaters = 0, max_repetitions = 3, varbinds = { { oid = "1.3.6.1.2.1.1" } } })
assert(#bulk.varbinds == 3 and bulk.varbinds[1].oid == "1.3.6.1.2.1.1.1.0" and bulk.varbinds[3].oid == "1.3.6.1.2.1.1.3.0")
local system = walk("1.3.6.1.2.1.1")
assert(#system >= 7, "the system group has at least seven scalars")
assert(#walk("1.3.6.1.2.1.2.2.1.2") == v[5].value, "one ifDescr per interface, as ifNumber says")
local addresses = walk("1.3.6.1.2.1.4.20.1.1")
assert(#addresses >= 1 and addresses[1].type == "ip_address", "the IP address table")
print("walk: getnext, getbulk, and walks of the system group (" .. #system .. " objects), the interfaces and the address table")

-- A packet the agent must ignore: the wrong community gets no answer at all.
assert(not pcall(ask, { community = "private", pdu = "get", varbinds = { { oid = "1.3.6.1.2.1.1.1.0" } } }, 1500))
print("community: no answer to a wrong community string")

-- Traps are fire-and-forget packets; snmptrapd on the host prints each one it receives.
local boot = { oid = "1.3.6.1.6.3.1.1.4.1.0", type = "oid", value = "1.3.6.1.6.3.1.1.5.1" }
udp:send(snmp.encode({ pdu = "trapv2", request_id = 7, varbinds = { { oid = "1.3.6.1.2.1.1.3.0", type = "time_ticks", value = 1000 }, boot } }), host, trap_port, timeout)
udp:send(snmp.encode({ version = "v1", pdu = "trap", enterprise = "1.3.6.1.4.1.9", agent_address = address,
    generic_trap = 6, specific_trap = 1, timestamp = 1000, varbinds = { { oid = "1.3.6.1.4.1.9.1", value = 1 } } }), host, trap_port, timeout)
print("traps: sent a v2c trap and a v1 trap")
udp:close()

-- Agent: answers from a small MIB of Lua values. Any script can do the same with its own data.
local mib = {
    { "1.3.6.1.2.1.1.1.0", "Kraken scripted device" },
    { "1.3.6.1.2.1.1.5.0", "kraken-lab" },
    { "1.3.6.1.2.1.1.7.0", 72 },
}
local function arcs(oid)
    local list = {}
    for arc in oid:gmatch("%d+") do list[#list + 1] = tonumber(arc) end
    return list
end
local function before(a, b)
    local x, y = arcs(a), arcs(b)
    for i = 1, math.max(#x, #y) do
        if (x[i] or -1) ~= (y[i] or -1) then return (x[i] or -1) < (y[i] or -1) end
    end
    return false
end
local function lookup(oid)
    for _, entry in ipairs(mib) do
        if entry[1] == oid then return { oid = oid, value = entry[2] } end
    end
    return { oid = oid, type = "no_such_object" }
end
local function following(oid)
    for _, entry in ipairs(mib) do
        if before(oid, entry[1]) then return { oid = entry[1], value = entry[2] } end
    end
    return { oid = oid, type = "end_of_mib_view" }
end

local listener = socket.udp.bind(identity, address, own_port)
print("agent: waiting for snmpget, snmpgetnext and snmpbulkget on " .. address .. ":" .. own_port)
local answered = {}
while not (answered.get and answered.getnext and answered.getbulk) do
    local bytes, peer, peer_port = listener:receive(120000)
    local request = snmp.decode(bytes)
    local response = { version = request.version, community = request.community, pdu = "response",
        request_id = request.request_id, varbinds = {} }
    if request.pdu == "get" then
        for _, varbind in ipairs(request.varbinds) do response.varbinds[#response.varbinds + 1] = lookup(varbind.oid) end
    elseif request.pdu == "getnext" then
        for _, varbind in ipairs(request.varbinds) do response.varbinds[#response.varbinds + 1] = following(varbind.oid) end
    elseif request.pdu == "getbulk" then
        local oid = request.varbinds[1].oid
        for _ = 1, request.max_repetitions do
            local varbind = following(oid)
            response.varbinds[#response.varbinds + 1] = varbind
            oid = varbind.oid
        end
    end
    if request.pdu then
        listener:send(snmp.encode(response), peer, peer_port, timeout)
        answered[request.pdu] = true
        print("agent: answered a " .. request.pdu)
    end
end
listener:close()
print("snmp experiment passed")
