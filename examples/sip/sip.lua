local identity = "base_192.168.122.5"
local address = "192.168.122.5"
local host = "192.168.122.1"
local port = 5060
local timeout = 5000

local socket = require("kraken/socket")
local sip = require("protocols/sip")
local std = require("kraken/std")

local udp = socket.udp.bind(identity, address, port)

local function header(message, name)
    for _, pair in ipairs(message.headers) do
        if pair[1]:lower() == name then return pair[2] end
    end
end

-- Receives one datagram: the decoded message and where it came from.
local function receive(wait)
    local bytes, peer, peer_port = udp:receive(wait or timeout)
    return sip.decode(bytes), peer, peer_port
end

local sdp = table.concat({
    "v=0", "o=kraken 1 1 IN IP4 " .. address, "s=-", "c=IN IP4 " .. address, "t=0 0",
    "m=audio 49170 RTP/AVP 0", "a=rtpmap:0 PCMU/8000", "",
}, "\r\n")

-- Client: the host's SIPp answers as a user agent server (`sipp -sn uas`).
local call_id = "kraken-1@" .. address
local from = "<sip:kraken@" .. address .. ">;tag=kraken1"
local branches = 0

local function request(method, uri, to, number, extra, body)
    branches = branches + 1
    local branch = "z9hG4bK-kraken-" .. branches
    local headers = {
        { "Via", "SIP/2.0/UDP " .. address .. ":" .. port .. ";branch=" .. branch },
        { "Max-Forwards", "70" }, { "From", from }, { "To", to }, { "Call-ID", call_id },
        { "CSeq", number .. " " .. method }, { "Contact", "<sip:kraken@" .. address .. ":" .. port .. ">" },
    }
    for _, pair in ipairs(extra or {}) do headers[#headers + 1] = pair end
    udp:send(sip.encode({ method = method, uri = uri, headers = headers, body = body }), host, port, timeout)
    return branch
end

-- Responses to a request carry its branch and CSeq; provisional ones come first.
local function final(branch, number, method)
    local statuses = {}
    while true do
        local reply = receive()
        assert(reply.status, "expected a response, got " .. tostring(reply.method))
        assert(header(reply, "via"):find("branch=" .. branch, 1, true), "a response for another transaction")
        assert(header(reply, "cseq") == number .. " " .. method)
        assert(header(reply, "call-id") == call_id)
        statuses[#statuses + 1] = reply.status
        if reply.status >= 200 then return reply, statuses end
    end
end

local target = "sip:service@" .. host .. ":" .. port
local to = "<" .. target .. ">"
local options = final(request("OPTIONS", target, to, 1), 1, "OPTIONS")
assert(options.status == 200)
print("client: OPTIONS answered " .. options.status .. " " .. options.reason)

local branch = request("INVITE", target, to, 2, { { "Content-Type", "application/sdp" } }, sdp)
local answer, statuses = final(branch, 2, "INVITE")
assert(answer.status == 200 and header(answer, "to"):find("tag=", 1, true), "INVITE was not answered 200 with a tag")
assert(answer.body:find("^v=0"), "the 200 carries no SDP")
print("client: INVITE answered " .. table.concat(statuses, ", ") .. " with " .. #answer.body .. " bytes of SDP")

-- The dialog is set up: ACK and BYE go to the contact, with the To header and its tag.
local contact = header(answer, "contact")
local remote = contact:match("<([^>]+)>") or contact:match("^%s*([^;%s]+)")
to = header(answer, "to")
request("ACK", remote, to, 2)
std.sleep(1000)   -- the call lasts a second; the ACK must also reach SIPp before the BYE
local bye = final(request("BYE", remote, to, 3), 3, "BYE")
assert(bye.status == 200)
print("client: BYE answered " .. bye.status)

-- Server: the host's SIPp calls in as a user agent client (`sipp -sn uac`). Responses are
-- built from the request: its Via, From, Call-ID and CSeq are copied, and To gets a tag.
local function respond(message, peer, peer_port, status, reason, extra, body)
    local headers = {}
    for _, pair in ipairs(message.headers) do
        local name = pair[1]:lower()
        if name == "via" or name == "from" or name == "call-id" or name == "cseq" then
            headers[#headers + 1] = pair
        elseif name == "to" then
            local value = pair[2]
            if status > 100 and not value:find("tag=", 1, true) then value = value .. ";tag=kraken-uas" end
            headers[#headers + 1] = { "To", value }
        end
    end
    for _, pair in ipairs(extra or {}) do headers[#headers + 1] = pair end
    udp:send(sip.encode({ status = status, reason = reason, headers = headers, body = body }), peer, peer_port, timeout)
end

print("server: waiting for SIPp's INVITE on " .. address .. ":" .. port)
local contact_header = { "Contact", "<sip:kraken@" .. address .. ":" .. port .. ">" }
local invited, acked, ended
while not ended do
    local message, peer, peer_port = receive(120000)
    assert(message.method, "expected a request")
    if message.method == "INVITE" then
        assert(header(message, "content-type") == "application/sdp" and message.body:find("^v=0"), "the INVITE carries no SDP")
        respond(message, peer, peer_port, 180, "Ringing", { contact_header })
        respond(message, peer, peer_port, 200, "OK", { contact_header, { "Content-Type", "application/sdp" } }, sdp)
        invited = true
        print("server: INVITE from " .. peer .. ":" .. peer_port .. " answered 180, 200")
    elseif message.method == "ACK" then
        acked = true
    elseif message.method == "BYE" then
        respond(message, peer, peer_port, 200, "OK")
        ended = true
    end
end
assert(invited and acked, "BYE arrived without a completed INVITE")
print("server: ACK received, BYE answered")
udp:close()
print("sip experiment passed")
