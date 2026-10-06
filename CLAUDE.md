# Kraken

Read [ENGINEERING.md](ENGINEERING.md) in full before changing code. Its requirements are binding; ask when the intended choice is unclear. Architecture overview: [README.md](README.md), [SCRIPTING.md](SCRIPTING.md), [supported_protocols.md](supported_protocols.md).

- Baseline for verification: ReleaseSmall tests (`zig build test -Doptimize=ReleaseSmall`); build both distributions when shared code or build inputs change.
- Report removals against a stated before/after baseline. If no worthwhile simplification exists, say so and leave the code alone.
