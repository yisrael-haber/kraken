local identity = "base_192.168.122.5"
local address = "192.168.122.5"
local host = "192.168.122.1"

local http = require("protocols/http")
local socket = require("kraken/socket")
local tls = require("protocols/tls")

-- The lab certificate from src/protocols/testdata (CN and SAN kraken.test),
-- which peer.py also uses. Each side verifies the other's certificate against it.
local certificate = [[
-----BEGIN CERTIFICATE-----
MIIBmDCCAT+gAwIBAgIUTCWRjKS3mXjBRYwU3b9YSIvwSgUwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLa3Jha2VuLnRlc3QwHhcNMjYwOTI1MTQxNzI0WhcNMzYwOTIy
MTQxNzI0WjAWMRQwEgYDVQQDDAtrcmFrZW4udGVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABAlPuxWAKkTzOmeYh+275W+8PcSUJ7gyzLofa8tYaHJqQvh0qXO2
vy5kgYfY8PqajbaGBlQCdnPv303/SrJvZT+jazBpMB0GA1UdDgQWBBT/+CXb9dus
c56X1ZX97xVEB/9M5TAfBgNVHSMEGDAWgBT/+CXb9dusc56X1ZX97xVEB/9M5TAP
BgNVHRMBAf8EBTADAQH/MBYGA1UdEQQPMA2CC2tyYWtlbi50ZXN0MAoGCCqGSM49
BAMCA0cAMEQCIDDsS4CI+1L6ODhUgCSvYtepBKAYLB/sz5euDgLBOtOzAiA+lKsX
fbL4lsjrI6stxuqWVOp1QFw/cnqDvIjnyyKOng==
-----END CERTIFICATE-----
]]
local key = [[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPio92wK/2YhZlSTq
G8gH2P0q7lauBWtRrW57ajjtjuChRANCAAQJT7sVgCpE8zpnmIftu+VvvD3ElCe4
Msy6H2vLWGhyakL4dKlztr8uZIGH2PD6mo22hgZUAnZz799N/0qyb2U/
-----END PRIVATE KEY-----
]]

-- protocols/http only converts between bytes and tables, so the same client and
-- server run over a TCP socket and over a TLS session: both have send/receive.
local transports = {
    {
        name = "http",
        port = 19091, -- the host's server
        listen = 19092, -- Kraken's server
        connect = function(tcp) return tcp end,
        accept = function(tcp) return tcp end,
    },
    {
        name = "https",
        port = 19093,
        listen = 19094,
        connect = function(tcp)
            local session = tls.connect(tcp, {
                server_name = "kraken.test",
                verify = true,
                ca = certificate,
                alpn = { "h2", "http/1.1" },
            }, 5000)
            local info = session:info()
            assert(info.alpn == "http/1.1" and #info.peer_certificates == 1)
            print("https client: " .. info.version .. " " .. info.cipher)
            return session
        end,
        accept = function(tcp)
            local session = tls.accept(tcp, {
                certificate = certificate,
                key = key,
                server_name = "kraken.test",
                alpn = { "http/1.1" },
            }, 5000)
            local info = session:info()
            assert(info.server_name == "kraken.test" and info.alpn == "http/1.1")
            print("https server: " .. info.version .. " " .. info.cipher)
            return session
        end,
    },
}

-- Receives until the head parses; returns the head and the bytes after it.
local function read_head(connection, parse)
    local data = ""
    while true do
        local head, length = parse(data)
        if head then return head, data:sub(length + 1) end
        data = data .. (connection:receive(4096, 5000) or error("peer closed before the head"))
    end
end

local function header(headers, name)
    for _, pair in ipairs(headers) do
        if pair[1]:lower() == name:lower() then return pair[2] end
    end
end

-- Client: GET `path` from the host, reading the body until the host closes.
local function get(transport, path)
    local connection = transport.connect(socket.tcp.connect(identity, host, transport.port, 5000))
    connection:send(http.request({
        method = "GET",
        path = path,
        headers = { { "Host", "kraken.test" }, { "Connection", "close" } },
    }), 5000)
    local head, body = read_head(connection, http.parse_response)
    for more in function() return connection:receive(4096, 5000) end do body = body .. more end
    connection:close()
    return head, body
end

-- Server: accept the host's POST and answer it.
local function serve(transport)
    local listener = socket.tcp.bind(identity, address, transport.listen)
    listener:listen()
    print(transport.name .. " server: waiting on " .. address .. ":" .. transport.listen)
    local connection = transport.accept(listener:accept(60000))
    local request, body = read_head(connection, http.parse_request)
    local length = tonumber(header(request.headers, "Content-Length"))
    while #body < length do body = body .. connection:receive(length - #body, 5000) end
    assert(request.method == "POST" and request.path == "/echo" and request.version == "1.1")
    assert(header(request.headers, "X-Test") == "a" and body == "ping")
    connection:send(http.response({
        status = 200,
        reason = "OK",
        headers = { { "Content-Length", "4" }, { "Connection", "close" } },
        body = "pong",
    }), 5000)
    connection:close()
    listener:close()
end

for _, transport in ipairs(transports) do
    local plain, plain_body = get(transport, "/plain")
    assert(plain.status == 200 and plain_body == "plain ok")
    local repeated = {}
    for _, pair in ipairs(plain.headers) do
        if pair[1] == "X-Kraken" then repeated[#repeated + 1] = pair[2] end
    end
    assert(#repeated == 2 and repeated[1] == "1" and repeated[2] == "2")
    local chunked, chunked_body = get(transport, "/chunked")
    assert(header(chunked.headers, "Transfer-Encoding") == "chunked")
    assert(http.dechunk(chunked_body) == "chunked ok")
    print(transport.name .. " client: duplicate headers and chunked body ok")
    serve(transport)
    print(transport.name .. " server: request parsed and answered")
end

print("http experiment passed")
