# Engineering and architecture principles

These requirements govern Kraken development. The goal is the smallest stable,
coherent design that supports its features and researcher capabilities. Feature
removal requires an explicit user instruction. Kraken is pre-alpha; backwards
compatibility does not justify a worse design. Update callers, examples and
documentation together when APIs or storage formats change.

These are requirements, not preferences. When the intended choice is unclear,
ask the user. The examples below describe actual earlier changes and their
reasoning; they do not depend on particular source files or prescribe the
current architecture. Principles without examples remain requirements.

## Requirements

- **Every line must justify itself.** Code must serve a concrete application
  need. Remove code that cannot justify its presence. Moving it, compressing
  formatting or exchanging it for equivalent complexity is not simplification.
- **Kraken logic belongs in Zig.** C is for external libraries and very basic
  glue, such as macros, inclusion and ABI accessors. Keep configuration and
  integration files in `vendor/<library>/kraken/`; shared binding includes live
  in `vendor/kraken/`. Translate public headers directly when no wrapper is
  needed. Exceptions require explicit authorization.
- **Keep stack access in the network frontend.** Application code calls the
  Zig API in `src/net/`; only that frontend accesses lwIP.
- **Trust external libraries.** Use their supported integration points without
  modifying their sources or protocol internals unless explicitly authorized.
  An approved adaptation, such as DCERPC over TCP, authorizes that integration
  only. Rely on the library's testing; test Kraken's integration where it adds
  application value.
- **Make ownership apparent.** Keep owners, borrowers and lifetimes clear in
  the code. Avoid scattered pointers, circular dependencies and indirect
  ownership. Synchronization and cleanup need a concrete purpose and owner.
- **Validate at the relevant boundary.** Security and stability are critical.
  Check incoming data once where validity matters, then rely on that contract.
  Each further check must address a distinct requirement. Repeated validation
  and defensive fallbacks obscure the guarantees and add cost.
- **Prefer coherent data over repeated translation.** A larger struct is
  preferable to representations continually converted and revalidated. Split
  them for a concrete benefit, such as a different lifetime or concurrency
  boundary, rather than saving a small amount of space.
- **Keep performance and allocations conservative.** Prefer direct ownership
  and allocation. Reserved memory can be worthwhile when it avoids allocation,
  copying or bookkeeping. Judge the overall design in context, not each unused
  byte. Simplicity does not excuse a material performance regression.
- **Make limits predictable.** Evaluate each limit against its purpose. Fixed
  capacities can make resource use understandable; reaching them must have a
  clear outcome and leave the application usable. Neither fixed limits nor
  configurability are goals by themselves.
- **Keep execution direct.** Avoid unnecessary virtualization, runtime
  indirection and frameworks. Use tagged unions for real distinctions and keep
  their control flow straightforward. A shared helper must remove duplication
  and simplify its callers.
- **Keep capabilities and APIs coherent.** Features must make sense individually
  and together. Offer and use internal APIs consistently, with clear contracts
  and responsibilities.
- **Choose the long-term design.** Identify compatibility baggage and other
  obstacles explicitly, with a default intent to remove them. Prefer complete,
  stable solutions over local patches. Research ownership and orchestration
  enough to resolve the actual problem, proportionately to its scope. Existing
  capabilities constrain the design; deletion, simplification and replacement
  are means of improving it, not separate agendas or line-count quotas.
- **Preserve researcher control.** Restrict capabilities only for a concrete
  application or library limitation, and explain it. A client-only library
  normally means offering a client unless a small adaptation or suitable
  alternative supports more. Deliberately strange packet behavior is valid
  when its meaning is clear. Do not reject or repair bytes, lengths, checksums
  or padding to impose preferred protocol behavior. Optional validation or
  repair, including defaults, needs an explicit researcher-accessible control.
- **Test for real stability.** Establish that Kraken is sane and usable through
  meaningful behavior and integration. Avoid assertions about incidental state
  or structure, constraints added for tests, and architecture contorted to keep
  them passing. Automated tests complement exercising the application.

## Examples of applying the principles

### Bring application state under its actual owner

The network adapter had two objects for each interface: a Zig owner pointing
to a separately allocated C wrapper containing the library's native interface.
Kraken's output queue and wake callback lived in C globals. Socket operations
crossed another wrapper API with integer operation codes.

Those layers split Kraken's ownership and logic across languages without an
independent responsibility. The Zig interface was changed to embed the native
interface and own its socket descriptors. The Zig backend owned its output
queue and called the library API directly. C retained only includes and an ABI
accessor. The library's own process-wide network thread remained library-owned.

The improvement was one interface allocation and an apparent queue owner, not
merely a translation of C into Zig. Integration checks exercised stream,
datagram and raw socket traffic without modifying library internals or adding
packet repair behavior.

### Stable addresses do not require separate owner wrappers

Application state was divided between separately allocated services, scratch
storage and an optional presentation wrapper. Callbacks found the application
through a global pointer, and cleanup ran from two places. The wrappers made
startup progress look like several independently optional lifetimes.

The application itself was already allocated at a stable address. Embedding its
services, scratch storage and UI preserved borrowed addresses while removing
two allocations and the wrappers. Callbacks received the application through
library user data. Each successful startup step registered local rollback;
normal shutdown had one cleanup path.

This justified a larger owner struct and necessary borrowed pointers. A startup
test retained allocation-failure and cleanup coverage while dropping assertions
that removed wrapper pointers must be null. Startup, resize and normal close
were also exercised on Linux.

### Express the connection choice once

Protocol adapters tracked an owned TCP transport, a pointer to the selected
transport and an optional TLS session. One adapter also added a type-erased
transfer callback. These fields described the same connection choice and needed
coordinated setup.

One tagged union represented an owned TCP transport or a borrowed TLS session.
The Lua user value kept the borrowed session alive. Shared deadline, transfer
and close operations removed duplicate setup and dispatch. The protocol
libraries still received callbacks through their required integration APIs;
those callbacks called the concrete connection directly.

Review also found that TLS close reset timeout state before one error path
reported it. Capturing the timeout before cleanup preserved the useful error.
Simpler ownership still needs correct sequencing. Protocol round trips, peer
failures and TLS integration were checked using a shared test pipe helper.

A library stream's free function delegated freeing the stream to its driver.
Kraken's empty release callback therefore leaked it. Reading that contract led
to cleanup in the adapter, including failed construction, without library edits.

### Make action ordering explicit

UI clicks passed through a C hover bridge to a global UI pointer and an action
pointer. A separate flag prevented repeated dispatch, and visual feedback also
suppressed subsequent clicks. A comment misdescribed when actions ran: records
were refreshed before callbacks processed bindings from the displayed layout.
That could associate displayed row indexes with different records.

The UI kept element-to-action bindings and dispatched once using the library's
updated pointer state, before refreshing records and building the next layout.
This removed the global pointer, bridge and suppression flag. The editor also
bound actions directly instead of using a type-erased callback. Feedback kept
its visual purpose without deciding whether another click was accepted.

Removing the exported callback unexpectedly dropped an unrelated storage test
from discovery. Importing that test's module explicitly restored coverage.
Release tests and builds passed, but clicks, menus, navigation and drag selection
were still unverified when this example was written: the GUI harness was
unreliable. The structural improvement did not establish preserved interaction
behavior.

### Rely on established guarantees

A network frontend allocated a queue mutex even though the library already
held its core lock while producing frames. Queue consumers switched to that
lock, removing the extra allocation, nested locking and cleanup method.
The library's synchronous input option also kept processing within the
interface's lifetime, avoiding queued input with a borrowed interface pointer.

The frontend also rejected inbound frames above the interface MTU and checked
copies whose source and destination sizes were already established. The MTU
restriction imposed application policy beyond the library's input requirements.
Removing it and the redundant copy checks retained allocation, submission and
buffer-capacity failures. Requiring a full-sized output buffer in the function
type removed a branch that silently discarded packets for smaller buffers.

The existing raw socket round trip exercised a frame larger than the receiving
interface's MTU; injection still rejected frames beyond application capacity.
This was a small source reduction that removed policy and failure branches.
Initialization state and socket ownership remained justified and were retained.

Capture also copied library-owned bytes into a temporary buffer before the
consumer copied them into its own storage. The consumer finished before the
next capture read, so returning a borrowed slice removed that intermediate copy
and buffer. The API documented the borrowing lifetime; asynchronous consumers
still received owned copies. Failed capture opens used local error cleanup,
removing a separate success flag.

## Working and verifying

Start with a concrete ownership, state, representation or execution problem.
Review each struct, field, method and branch for the responsibility it serves;
being used does not by itself justify it. Evaluate removals across their callers
so moving state or adding request plumbing is not mistaken for simplification.
Trace call order and library contracts; comments and wrapper names can mislead.
Reading library behavior to understand integration does not justify patching
it. Establish architectural boundaries before cleaning up their symptoms.

Explain what disappears, why the remaining code is justified and which
capabilities must hold. Report meaningful code removal, API or format changes
and evidence of preserved behavior. Use a stated before/after baseline for
counts. If no worthwhile simplification is established, report that and leave
the code alone. Add examples for other principles only after real work supplies
them.

Use ReleaseSmall tests as the primary baseline. Verify both distribution builds
when shared code or build inputs change, and exercise relevant workflows where
tests lack coverage. Known library Debug failures do not authorize changes to
trusted internals. State unavailable platform checks and leave verification
gaps explicit; tests and builds alone do not establish interactive behavior.

Verification should answer a specific remaining question. Repeat passing checks
only for new changes, failures or unresolved concerns. If a harness becomes the
problem, report the gap and choose a bounded relevant alternative. Repeated
unchanged builds and open-ended harness debugging do not close it. State the
result and remaining work clearly.

## Known gaps

- `packet.encode` and `packet.fragment` build into a 2,048-byte frame, which
  blocks fragmenting a datagram larger than a frame.
- Interactive UI behavior and Windows execution are not covered by automated
  tests; Windows is only cross-built.
- TLS and Telnet-over-TLS timeout recovery is covered over in-memory pipes;
  live-peer execution of those paths remains unverified.
