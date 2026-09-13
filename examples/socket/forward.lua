-- Repair captured checksums before forwarding, including on checksum-offloaded VM links.
local packet = require("kraken/packet")

function transport(bytes, tx)
    tx.send(packet.encode(packet.decode(bytes)))
end
