local identity = "base_192.168.122.5"
local host = "192.168.122.1"
local timeout = 5000

local socket = require("kraken/socket")
local smtp = require("protocols/smtp")
local pop3 = require("protocols/pop3")
local imap = require("protocols/imap")

-- SMTP: send one message to the host's aiosmtpd, naming ourselves in EHLO.
local mail = smtp.connect(socket.tcp.connect(identity, host, 25, timeout), { hostname = "kraken.lab" }, timeout)
local info = mail:info()
local offered = {}
for name in pairs(info.extensions) do offered[#offered + 1] = name end
table.sort(offered)
print("smtp: connected, the server said " .. info.code .. " " .. info.response:gsub("\n", " | ") .. "; extensions: " .. table.concat(offered, ", "))
mail:send({
    from = "kraken@lab.test",
    to = { "alice@example.test", "bob@example.test" },
    message = "From: kraken@lab.test\r\nTo: alice@example.test, bob@example.test\r\nSubject: hello from kraken\r\n\r\nline one\r\n.line two starts with a dot\r\n",
}, timeout)
print("smtp: sent one message to two recipients; the server said: " .. mail:info().response)
mail:close()

-- POP3: Dovecot has two messages for the user "test", password "secret".
local wrong = pop3.connect(socket.tcp.connect(identity, host, 110, timeout), timeout)
local ok, err = pcall(wrong.login, wrong, "test", "wrong", timeout)
assert(not ok and err:find("PASS failed", 1, true), err)
wrong:close()
print("pop3: a wrong password was refused: " .. err:match("POP3 PASS failed: [^\n]*"))

mail = pop3.connect(socket.tcp.connect(identity, host, 110, timeout), timeout)
mail:login("test", "secret", timeout)
local count, size = mail:stat(timeout)
assert(count == 2, "expected two messages, found " .. count)
local list = mail:list(timeout)
assert(#list == 2 and list[1].uidl and list[2].uidl, "the listing has no UIDLs")
assert(mail:retrieve(1, timeout):find("Subject: First message", 1, true))
assert(mail:top(2, 1, timeout):find("Subject: Second message", 1, true))
mail:delete(2, timeout)
mail:reset(timeout)
print("pop3: " .. count .. " messages, " .. size .. " bytes; retrieved the first, read the head of the second, deleted and restored it")
mail:close()
-- IMAP: the same mailbox, through Dovecot's IMAP service.
local wrong_login = imap.connect(socket.tcp.connect(identity, host, 143, timeout), timeout)
ok, err = pcall(wrong_login.login, wrong_login, "test", "wrong", timeout)
assert(not ok and err:find("IMAP LOGIN failed", 1, true), err)
wrong_login:close()
print("imap: a wrong password was refused: " .. err:match("IMAP LOGIN failed: [^\n]*"))

local box = imap.connect(socket.tcp.connect(identity, host, 143, timeout), timeout)
box:login("test", "secret", timeout)
local names = {}
for _, entry in ipairs(box:list("", "*", timeout)) do names[#names + 1] = entry.name end
assert(names[1] == "INBOX" or table.concat(names, ","):find("INBOX", 1, true), "no INBOX")
local inbox = box:select("INBOX", false, timeout)
assert(inbox.exists == 2 and inbox.uidvalidity, "expected two messages")
assert(#box:search({}, timeout) == 2)
local subjects = ""
for _, message in ipairs(box:fetch("1:2", { "flags", "uid", "size", "header" }, timeout)) do
    assert(message.uid and message.size and message.flags)
    subjects = subjects .. message.header
end
assert(subjects:find("Subject: First message", 1, true) and subjects:find("Subject: Second message", 1, true))
assert(box:fetch(1, { "body" }, timeout)[1].body:find("body", 1, true))
box:store(1, "add", { "\\Seen" }, timeout)
local seen = box:search({ seen = true }, timeout)
local has_first = false
for _, number in ipairs(seen) do has_first = has_first or number == 1 end
assert(has_first, "the first message is not \\Seen")
box:append("INBOX", "From: kraken@lab.test\r\nSubject: appended\r\n\r\nvia IMAP\r\n", timeout)
assert(box:select("INBOX", false, timeout).exists == 3, "the appended message is missing")
box:store(3, "add", { "\\Deleted" }, timeout)
box:expunge(timeout)
assert(box:select("INBOX", false, timeout).exists == 2, "the appended message was not expunged")
box:create("Lab", timeout)
box:delete("Lab", timeout)
print("imap: two messages; read their heads and the first body, flagged one \\Seen, appended a message and expunged it")
box:close()
print("mail experiment passed")
