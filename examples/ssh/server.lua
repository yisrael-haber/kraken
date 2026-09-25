local identity = "base_192.168.122.5"
local address = "192.168.122.5"

local socket = require("kraken/socket")
local ssh = require("protocols/ssh")

-- A lab ECDSA (P-256) host key in DER, hex-encoded. Generate your own with:
--   openssl ecparam -name prime256v1 -genkey -noout -outform DER -out host.der
--   od -An -v -tx1 host.der | tr -d ' \n'
-- The host's ssh client accepts it with StrictHostKeyChecking=no.
local host_key_hex =
    "30770201010420351e5b29d67c7e3657d557734f976e1ab7dce1ab5c858336e514318d4413f5db" ..
    "a00a06082a8648ce3d030107a1440342000407dd6b7d45442eee8e5e9aae45f8ce360aa2282bc4" ..
    "f287db9c7f191bc0a0fe199da83f9f18a181b4fb380f422e9f9203fa9aaea947a921dfce66e808" ..
    "3fc7c82a"

local function unhex(text)
    return (text:gsub("%x%x", function(pair) return string.char(tonumber(pair, 16)) end))
end

-- Accept any login: log what was offered. Tighten in real experiments.
local function authorize(username, method, secret)
    print(string.format("auth: user=%s method=%s (%d bytes)", username, method, #secret))
    return true
end

local listener = socket.tcp.bind(identity, address, 19096)
listener:listen()
print("server: waiting for an SSH client on " .. address .. ":19096")
local peer = listener:accept(120000)
local session = ssh.accept(peer, {
    host_key = unhex(host_key_hex),
    authorize = authorize,
}, 10000)
local command = session:command()
print("server: client asked to run: " .. tostring(command))
session:send("kraken ran: " .. tostring(command) .. "\n", 5000)
session:close(0)
listener:close()

print("ssh experiment passed")
