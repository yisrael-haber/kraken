local identity = "base_192.168.122.5"
local address = "192.168.122.5"
local host = "192.168.122.1"
local host_port = 6969   -- peer.py
local own_port = 6970    -- this script's server
local timeout = 5000

local socket = require("kraken/socket")
local tftp = require("protocols/tftp")

-- The same repeating bytes as peer.py, so each side can check what it received.
local function pattern(size)
    local bytes = {}
    for i = 0, size - 1 do bytes[#bytes + 1] = string.char((i * 7 + 3) % 251) end
    return table.concat(bytes)
end

local function expect(packet, op)
    if packet.op == "error" then error("peer: " .. packet.message, 0) end
    assert(packet.op == op, "expected " .. op .. ", got " .. tostring(packet.op))
    return packet
end

-- TFTP is lock-step: DATA block n, then its ACK. A block shorter than the block size
-- ends the transfer, which is an empty block when the size is an exact multiple.
local function send_blocks(udp, peer, peer_port, data, blksize)
    local block, offset = 1, 1
    repeat
        local chunk = data:sub(offset, offset + blksize - 1)
        udp:send(tftp.encode({ op = "data", block = block, data = chunk }), peer, peer_port, timeout)
        local ack = expect(tftp.decode((udp:receive(timeout))), "ack")
        assert(ack.block == block, "ack for block " .. ack.block .. ", expected " .. block)
        block, offset = block + 1, offset + blksize
    until #chunk < blksize
end

-- Acknowledges DATA blocks from the peer's transfer port until a short one. `packet` is
-- a packet already read (the peer's first reply), or nil.
local function receive_blocks(udp, peer, peer_port, blksize, packet)
    local parts, expected = {}, 1
    while true do
        if not packet then
            local bytes, from, from_port = udp:receive(timeout)
            if from == peer and from_port == peer_port then packet = tftp.decode(bytes) end
        end
        if packet and packet.op == "data" and packet.block == expected then
            parts[#parts + 1] = packet.data
            udp:send(tftp.encode({ op = "ack", block = expected }), peer, peer_port, timeout)
            if #packet.data < blksize then return table.concat(parts) end
            expected = expected + 1
        elseif packet then
            expect(packet, "data")
        end
        packet = nil
    end
end

-- Client: a request to the server's port, then everything else with the port it answers from.
local function get(local_port, name, options)
    local udp = socket.udp.bind(identity, address, local_port)
    udp:send(tftp.encode({ op = "rrq", filename = name, mode = "octet", options = options }), host, host_port, timeout)
    local ok, result = pcall(function()
        local bytes, peer, peer_port = udp:receive(timeout)
        local reply = tftp.decode(bytes)
        local blksize = 512
        if reply.op == "oack" then
            blksize = tonumber(reply.options.blksize) or blksize
            udp:send(tftp.encode({ op = "ack", block = 0 }), peer, peer_port, timeout)
            reply = nil
        end
        return receive_blocks(udp, peer, peer_port, blksize, reply)
    end)
    udp:close()
    return assert(ok, result) and result
end

local function put(local_port, name, data, options)
    local udp = socket.udp.bind(identity, address, local_port)
    udp:send(tftp.encode({ op = "wrq", filename = name, mode = "octet", options = options }), host, host_port, timeout)
    local ok, result = pcall(function()
        local bytes, peer, peer_port = udp:receive(timeout)
        local reply = tftp.decode(bytes)
        local blksize = 512
        if reply.op == "oack" then blksize = tonumber(reply.options.blksize) or blksize else expect(reply, "ack") end
        send_blocks(udp, peer, peer_port, data, blksize)
    end)
    udp:close()
    assert(ok, result)
end

local download = pattern(2500)
assert(get(6971, "download.bin") == download, "download.bin differs")
assert(get(6972, "download.bin", { blksize = 1024 }) == download, "download.bin with blksize 1024 differs")
assert(get(6973, "exact.bin") == pattern(1024), "exact.bin (a whole number of blocks) differs")
local ok, refused = pcall(get, 6974, "missing.bin")
assert(not ok and refused:find("File not found", 1, true), refused)
print("client: read 2500 bytes in 512- and 1024-byte blocks, an exact multiple of the block size, and a refusal")

put(6975, "upload.bin", pattern(3000))
put(6976, "upload.bin", pattern(3000), { blksize = 1024 })
print("client: wrote 3000 bytes with and without a blksize option; peer.py reports whether they arrived intact")

-- Server: a request arrives on our port; the transfer runs from a new port, its TID.
-- It stops once one read and one write have completed; a repeated request is ignored.
local files = { ["kraken.bin"] = pattern(1500) }
local listener = socket.udp.bind(identity, address, own_port)
print("server: waiting for a read and a write request on " .. address .. ":" .. own_port)
local read_done, write_done, tid_port = false, false, 6980
while not (read_done and write_done) do
    local bytes, peer, peer_port = listener:receive(120000)
    local request = tftp.decode(bytes)
    tid_port = tid_port + 1
    local udp = socket.udp.bind(identity, address, tid_port)
    local blksize = tonumber(request.options and request.options.blksize)
    local function accept()
        if blksize then
            udp:send(tftp.encode({ op = "oack", options = { blksize = blksize } }), peer, peer_port, timeout)
        elseif request.op == "wrq" then
            udp:send(tftp.encode({ op = "ack", block = 0 }), peer, peer_port, timeout)
        end
    end
    if request.op == "rrq" and files[request.filename] then
        accept()
        if blksize then expect(tftp.decode((udp:receive(timeout))), "ack") end
        send_blocks(udp, peer, peer_port, files[request.filename], blksize or 512)
        print("server: sent " .. request.filename)
        read_done = true
    elseif request.op == "wrq" and request.filename == "incoming.bin" then
        accept()
        local data = receive_blocks(udp, peer, peer_port, blksize or 512)
        assert(data == pattern(2200), "incoming.bin differs")
        print("server: received incoming.bin, " .. #data .. " bytes, intact")
        write_done = true
    else
        udp:send(tftp.encode({ op = "error", code = 1, message = "File not found" }), peer, peer_port, timeout)
        print("server: refused " .. tostring(request.op) .. " " .. tostring(request.filename))
    end
    udp:close()
end
listener:close()
print("tftp experiment passed")
