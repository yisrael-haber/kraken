-- Split outbound IPv4 datagrams into researcher-controlled fragments without changing their DF flag.
local mtu = 576

function transport(packet, direction)
    if direction == "outbound" and packet.ip then
        for _, fragment in ipairs(kraken.fragment(packet, mtu)) do fragment:send() end
        return
    end
    packet:send()
end
