-- One Kraken global script. Edit these values, then run the whole script.
local identity = "researcher"  -- running Kraken identity
local address = "192.0.2.20"   -- Windows IPv4 address
local computer = "WIN10"       -- Windows computer name (hostname)
local username = "kraken-test" -- local account with a password, not a PIN
local password = "change-me"

local share_name = "KrakenProbe"
local timeout = 5000
local socket = require("kraken/socket")
local smb = require("protocols/smb")
local dcerpc = require("protocols/dcerpc")

local function connect(port)
    return socket.tcp.connect(identity, address, port, timeout)
end

local function check_rpc(reply, procedure)
    assert(reply:find('"' .. procedure .. '"', 1, true), "wrong RPC response: " .. reply)
    local status = tonumber(reply:match('"Status"%s*:%s*(%d+)'))
    assert(status == 0, procedure .. " returned status " .. tostring(status) .. ": " .. reply)
end

local function test_smb()
    local files = smb.connect(connect(445), {
        server = computer, share = share_name, username = username,
        password = password, domain = computer, sign = true,
    }, timeout)
    math.randomseed(os.time(), math.floor(os.clock() * 1000000))
    local root = "kraken-probe-" .. os.time() .. "-" .. math.random(1000000)
    local folder = root .. "/nested"
    local first, renamed = folder .. "/first.bin", folder .. "/renamed.bin"
    local block = string.rep("0123456789abcdef", 2048) -- exactly 32768 bytes
    local tail = "\0\255Kraken" -- binary data after the first block
    local ok, err = pcall(function()
        files:mkdir(root, timeout)
        files:mkdir(folder, timeout)
        assert(files:write(first, block, 0, timeout) == #block, "first SMB write was short")
        assert(files:write(first, tail, #block, timeout) == #tail, "second SMB write was short")
        assert(files:stat(first, timeout).size == #block + #tail, "SMB size is wrong")
        assert(files:read(first, #block, 0, timeout) == block, "first SMB read differs")
        assert(files:read(first, #tail, #block, timeout) == tail, "binary SMB read differs")
        assert(files:write(first, "patch", 100, timeout) == 5, "offset SMB write was short")
        assert(files:read(first, 16, 96, timeout) == block:sub(97, 100) .. "patch" .. block:sub(106, 112), "offset write differs")
        assert(files:read(first, 1, #block + #tail, timeout) == "", "SMB EOF is not empty")
        files:rename(first, renamed, timeout)
        local found, old = false, false
        for _, entry in ipairs(files:list(folder, timeout)) do
            if entry.name == "renamed.bin" then found = true end
            if entry.name == "first.bin" then old = true end
        end
        assert(found and not old, "SMB listing did not reflect rename")
        files:remove(renamed, timeout)
        files:rmdir(folder, timeout)
        files:rmdir(root, timeout)
    end)
    if not ok then
        -- Only touch names created by this run; a failed session may already be closed.
        pcall(function() files:remove(renamed, timeout) end)
        pcall(function() files:remove(first, timeout) end)
        pcall(function() files:rmdir(folder, timeout) end)
        pcall(function() files:rmdir(root, timeout) end)
    end
    files:close()
    assert(ok, "SMB failed; inspect " .. root .. " if it remains: " .. tostring(err))
    print("PASS SMB: binary, offsets, EOF, stat, list, rename, cleanup")
end

local function test_rpc_smb()
    local rpc = dcerpc.smb(connect(445), {
        server = computer, service = "srvsvc", username = username,
        password = password, domain = computer, sign = true,
    }, timeout)
    local request = '{"NetrShareEnum":{"InfoStruct":{"Level":1,"ShareInfo":{}},"PreferedMaximumLength":4294967295}}'
    local reply = rpc:call("NetrShareEnum", request, timeout)
    rpc:close()
    check_rpc(reply, "NetrShareEnum")
    assert(reply:lower():find(share_name:lower(), 1, true), "share missing from srvsvc result: " .. reply)
    print("PASS DCERPC/SMB: authenticated srvsvc bind and share enumeration")
end

local function test_rpc_tcp()
    -- Port 135 is the endpoint mapper itself; no dynamic port or RPC auth.
    local rpc = dcerpc.tcp(connect(135), { service = "epmapper" }, timeout)
    local request = '{"Lookup":{"InquiryType":0,"VersOption":1,"EntryHandle":{"ContextHandleAttributes":0,"UUID":"00000000-0000-0000-0000-000000000000"},"MaxEnts":1}}'
    local reply = rpc:call("Lookup", request, timeout)
    rpc:close()
    check_rpc(reply, "Lookup")
    local count = tonumber(reply:match('"NumEnts"%s*:%s*(%d+)'))
    assert(count and count > 0, "endpoint mapper returned no entries: " .. reply)
    print("PASS DCERPC/TCP: endpoint mapper bind and lookup")
end

test_smb()
test_rpc_smb()
test_rpc_tcp()
print("PASS all SMB/DCERPC checks")
