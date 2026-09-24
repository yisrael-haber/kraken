local identity = "researcher"
local host = "192.0.2.1"
local port = 19090

local socket = require("kraken/socket")

local tcp = socket.tcp.connect(identity, host, port, 5000)
tcp:send("kraken tcp\n", 5000)
assert(tcp:receive(7, 5000) == "tcp ok\n")
tcp:close()

local udp = socket.udp.connect(identity, host, port)
udp:send("kraken udp", 5000)
local reply, address, reply_port = udp:receive(5000)
assert(reply == "udp ok")
assert(address == host)
assert(reply_port == port)
udp:close()

print("socket experiment passed")
