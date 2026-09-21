-- Split outbound IPv4 datagrams into researcher-controlled fragments without changing their DF flag.
local mtu = 576
local packet = require("kraken/packet")
local transmit = require("kraken/transmit")

function transport(bytes, identity, direction)
    local frame = packet.decode(bytes)
    if direction == "outbound" and frame.ip then
        for _, fragment in ipairs(packet.fragment(frame, mtu)) do transmit(identity, packet.encode(fragment), direction) end
        return
    end
    transmit(identity, packet.encode(frame), direction)
end
