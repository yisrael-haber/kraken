-- Expose an identity for a timed experiment. Cancelling the script leaves the identity running.
local identity = "researcher"
local duration_ms = 10000

start_identity(identity)
print("identity running for " .. duration_ms .. " ms")
kraken.sleep(duration_ms)
stop_identity(identity)
