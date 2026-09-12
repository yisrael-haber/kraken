-- A direction-independent TCP flow key for per-connection transport state.
local flow = {}

function flow.tcp_key(packet)
    if not packet.ip or not packet.tcp then return nil end
    local source = tostring(packet.ip.src) .. ":" .. packet.tcp.srcport
    local destination = tostring(packet.ip.dst) .. ":" .. packet.tcp.dstport
    if source < destination then return source .. " <-> " .. destination end
    return destination .. " <-> " .. source
end

return flow
