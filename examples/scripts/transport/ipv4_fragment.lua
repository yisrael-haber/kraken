-- Split outbound IPv4 datagrams into researcher-controlled fragments without changing their DF flag.
local mtu = 576
local packet = require("kraken/packet")

function transport(bytes, tx)
    local frame = packet.decode(bytes)
    if tx.direction == "outbound" and frame.ip then
        for _, fragment in ipairs(packet.fragment(frame, mtu)) do tx.send(packet.encode(fragment)) end
        return
    end
    tx.send(packet.encode(frame))
end
