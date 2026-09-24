-- Repair captured checksums before forwarding, including on checksum-offloaded VM links.
local packet = require("kraken/packet")
local transmit = require("kraken/transmit")

function transport(bytes, identity, direction)
    transmit(identity, packet.encode(packet.decode(bytes)), direction)
end
