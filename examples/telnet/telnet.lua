local identity = "base_192.168.122.5"
local address = "192.168.122.5"
local host = "192.168.122.1"
local port = 23
local timeout = 5000

local socket = require("kraken/socket")
local telnet = require("protocols/telnet")

-- Client: connect to the host's telnetd and read up to its login prompt. The session
-- answers the server's negotiation by its lists: it will send a terminal type, and lets
-- the server echo and suppress go-ahead. The script sees each negotiation as an event and
-- answers the one request the lists cannot, the server asking what the terminal type is.
local session = telnet.session(socket.tcp.connect(identity, host, port, timeout), {
    us = { "terminal_type" },
    them = { "echo", "sga" },
})
local text, negotiations = "", 0
while not text:find("login:", 1, true) do
    local data, events = session:receive(4096, timeout)
    assert(data, "closed before the login prompt")
    text = text .. data
    for _, event in ipairs(events) do
        if event.type == "subnegotiation" and event.option == telnet.options.terminal_type and event.data == "\1" then
            session:subnegotiate("terminal_type", "\0XTERM")   -- IS XTERM
        elseif event.type ~= "subnegotiation" then
            negotiations = negotiations + 1
        end
    end
end
assert(negotiations > 0, "the server negotiated nothing")
print("client: " .. negotiations .. " negotiations, then the prompt " .. text:match("([^\r\n]*login:)"))
session:close()

-- Server: the host's telnet client connects. The server offers to echo, asks for the
-- terminal type and sends a greeting, then reads one line and answers it.
local listener = socket.tcp.bind(identity, address, port)
listener:listen()
print("server: waiting for the host's telnet client on " .. address .. ":" .. port)
local peer = listener:accept(120000)
listener:close()
session = telnet.session(peer, { us = { "echo", "sga" }, them = { "terminal_type" } })
session:negotiate("will", "echo")
session:negotiate("will", "sga")
session:negotiate("do", "terminal_type")
session:send("Kraken telnet server\r\n")

local line, terminal = "", nil
while not line:find("\n", 1, true) do
    local data, events = session:receive(4096, 10000)
    assert(data, "closed before a line arrived")
    line = line .. data
    for _, event in ipairs(events) do
        if event.type == "will" and event.option == telnet.options.terminal_type then
            session:subnegotiate("terminal_type", "\1")   -- SEND
        elseif event.type == "subnegotiation" and event.option == telnet.options.terminal_type then
            terminal = event.data:sub(2)
        end
    end
end
line = line:match("^(.-)\r?\n")
print("server: the client sent \"" .. line .. "\", terminal type " .. tostring(terminal))
session:send("you said: " .. line .. "\r\n")
session:close()
print("telnet experiment passed")
