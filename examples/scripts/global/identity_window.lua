-- Expose an identity for a timed experiment. Cancelling the script leaves the identity running.
local identities = require("kraken/identities")
local std = require("kraken/std")
local identity = "researcher"
local duration_ms = 10000

identities.start(identity)
print("identity running for " .. duration_ms .. " ms")
std.sleep(duration_ms)
identities.stop(identity)
