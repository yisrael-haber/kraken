local identity = "base_192.168.122.5" -- running Kraken identity
local address = "192.168.122.248"      -- Windows IPv4 address
local computer = "DESKTOP-V9FBTJV"               -- Windows computer name (hostname)
local username = "yisrael"         -- local account with a password, not a PIN
local password = "yisrael"           -- do not save or share a real password

local share_name = "yisrael-kraken"
local timeout = 5000
local socket = require("kraken/socket")
local smb = require("protocols/smb")
local dcerpc = require("protocols/dcerpc")

local function connect(port)
    return socket.tcp.connect(identity, address, port, timeout)
end

local function check_rpc(reply, procedure)
    local result = reply[procedure]
    assert(result and result.Status == 0, procedure .. " failed with status " .. tostring(result and result.Status))
    return result
end

-- True when a string anywhere in the decoded reply contains `text` (ignoring case).
local function mentions(value, text)
    if type(value) == "string" then return value:lower():find(text:lower(), 1, true) ~= nil end
    if type(value) ~= "table" then return false end
    for _, item in pairs(value) do
        if mentions(item, text) then return true end
    end
    return false
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
    local reply, yaml = rpc:call("NetrShareEnum", [[
NetrShareEnum: Request
  ServerName: \\]] .. address .. [[

  InfoStruct:
    Level: 1
    ShareInfo:
  PreferedMaximumLength: 0xffffffff
  ResumeHandle: 0
]], timeout)
    rpc:close()
    check_rpc(reply, "NetrShareEnum")
    assert(mentions(reply, share_name), "share missing from srvsvc result: " .. yaml)
    print("PASS DCERPC/SMB: authenticated srvsvc bind and share enumeration")
end

local function test_rpc_smb_raw()
    -- srvsvc by UUID on its named pipe, no procedure table. NetrRemoteTOD (opnum 28)
    -- takes a null server name; the reply stub is a pointer, the 12-word
    -- TIME_OF_DAY_INFO, and the status.
    local rpc = dcerpc.smb(connect(445), {
        server = computer, interface = "4b324fc8-1670-01d3-1278-5a47bf6ee188", version = "3.0",
        pipe = "srvsvc", username = username, password = password, domain = computer, sign = true,
    }, timeout)
    local reply = rpc:call(28, string.pack("<I4", 0), timeout)
    rpc:close()
    assert(#reply == 56, "unexpected NetrRemoteTOD reply length " .. #reply)
    local year = string.unpack("<I4", reply, 45)
    local status = string.unpack("<I4", reply, 53)
    assert(status == 0 and year >= 2000 and year < 2100, "raw NetrRemoteTOD failed: status " .. status .. ", year " .. year)
    print("PASS DCERPC/SMB raw: interface UUID, pipe, opnum 28, hand-packed NDR stub")
end

local function test_rpc_tcp()
    -- Port 135 is the endpoint mapper itself; no dynamic port or RPC auth.
    local rpc = dcerpc.tcp(connect(135), { service = "epmapper", ndr = "32" }, timeout)
    assert(rpc:template("Lookup"):find("MaxEnts", 1, true), "Lookup template has no MaxEnts")
    local reply = rpc:call("Lookup", [[
Lookup: Request
  InquiryType: 0
  VersOption: 1
  EntryHandle:
    ContextHandleAttributes: 0
    UUID: 00000000-0000-0000-0000-000000000000
  MaxEnts: 1
]], timeout)
    rpc:close()
    local lookup = check_rpc(reply, "Lookup")
    assert(lookup.NumEnts > 0, "endpoint mapper returned no entries")
    assert(#lookup.Entries[1].Tower.TowerOctetString > 0, "endpoint tower missing")
    print("PASS DCERPC/TCP: endpoint mapper bind and named Lookup")
end

local function test_rpc_raw()
    -- The same call with no libdcerpc procedure table: any interface by UUID, an
    -- opnum, and the NDR stub packed by hand. EPM Lookup (opnum 2): inquiry type,
    -- null object and interface pointers, version option, entry handle, max entries.
    local rpc = dcerpc.tcp(connect(135), {
        interface = "e1af8308-5d1f-11c9-91a4-08002b14a0fa", version = "3.0",
    }, timeout)
    local stub = string.pack("<I4I4I4I4I4c16I4", 0, 0, 0, 1, 0, string.rep("\0", 16), 1)
    local reply = rpc:call(2, stub, timeout)
    rpc:close()
    -- Reply stub: entry handle (20 bytes), NumEnts, ..., status in the last 4 bytes.
    local count = string.unpack("<I4", reply, 21)
    local status = string.unpack("<I4", reply, #reply - 3)
    assert(status == 0 and count > 0, "raw Lookup failed: status " .. status .. ", entries " .. count)
    print("PASS DCERPC/TCP raw: interface UUID, opnum 2, hand-packed NDR stub")
end

test_smb()
test_rpc_smb()
test_rpc_smb_raw()
test_rpc_tcp()
test_rpc_raw()
print("smb dcerpc experiment passed")
