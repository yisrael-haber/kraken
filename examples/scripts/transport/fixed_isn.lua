-- Translate TCP sequence and acknowledgement numbers so external flows start at 12345678.
local forced_isn = 12345678
local sequence_space = 4294967296
local flow_key = require("flow").tcp_key
local flows = {}

function transport(packet, direction)
    if not packet.tcp then return packet:send() end
    local key = flow_key(packet)
    local flow = flows[key]

    if direction == "outbound" then
        if packet.tcp.flags.syn and (not flow or flow.internal_syn ~= packet.tcp.seq) then
            flow = {
                internal_syn = packet.tcp.seq,
                offset = (forced_isn - packet.tcp.seq) % sequence_space,
            }
            flows[key] = flow
            print("TCP SYN " .. key .. ": " .. packet.tcp.seq .. " -> " .. forced_isn)
        end
        if flow then packet.tcp.seq = (packet.tcp.seq + flow.offset) % sequence_space end
    elseif flow and packet.tcp.flags.ack then
        packet.tcp.ack = (packet.tcp.ack - flow.offset) % sequence_space
    end
    packet:send()
    if packet.tcp.flags.reset then flows[key] = nil end
end
