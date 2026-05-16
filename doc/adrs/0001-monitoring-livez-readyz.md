# 0001. Kubernetes-style `/livez` and `/readyz` monitoring

- Date: 2026-05-16
- Status: Accepted

## Context and Motivation

khaled runs as a Kubernetes workload (a StatefulSet, deployed via the
in-tree Helm chart). Kubernetes wants two distinct signals from a pod:

- **Liveness** — should the process be restarted? A failing liveness
  probe causes the kubelet to kill and recreate the container.
- **Readiness** — should this pod receive traffic? A failing readiness
  probe removes the pod from its Service's `EndpointSlices`.

Before this change khaled exposed neither. Its only HTTP surface was the
CKAP transport: an mTLS listener that requests a client certificate and
serves CKAP over TLS 1.3. With no probe endpoints, Kubernetes could only
fall back to a TCP check against that port — which says nothing about
whether khaled's subsystems are actually healthy, cannot distinguish
liveness from readiness, and gives an operator no diagnostic when a pod
is stuck.

Two further problems motivated a careful design rather than a quick
endpoint bolt-on:

1. **Slow or hung startup.** khaled's startup depends on external
   systems — notably the SPIFFE Workload API for server certificates. If
   one hangs, an operator needs a signal that says *which* dependency is
   unfinished, not a blind connection-refused.

2. **Graceful shutdown.** When a pod is deleted, closing the CKAP
   listener immediately races endpoint deregistration: in-flight and
   freshly-routed CKAP requests can hit a socket that is already gone.

This ADR records how the probes are surfaced, configured, and what
"ready" means.

## Options Considered

### Probe surface

#### A. Dedicated plaintext admin listener

A separate, plaintext (non-TLS) HTTP listener on its own address,
carrying only `/livez` and `/readyz`. The kubelet probes it directly.
This is the pattern kube-apiserver, etcd and the controller-manager use:
a clean split between the data plane and the operational plane.

##### Pros/cons

- **Pro:** kubelet HTTP-GET probes work out of the box — no client
  certificate, no TLS handshake to negotiate.
- **Pro:** probes are reachable before the CKAP listener's TLS
  certificate source has produced a certificate.
- **Pro:** keeps an unauthenticated operational surface entirely out of
  the mTLS data plane.
- **Con:** binds a second port; one more thing to configure and to
  reason about in network policy.

#### B. Mount probes on the existing CKAP listeners

Add `/livez` and `/readyz` to each `listeners[]` mux, bypassing the
authn/claims middleware so the probes are unauthenticated.

##### FAQ

- *Can the kubelet probe an mTLS listener?* Only awkwardly. The kubelet
  presents no client certificate; the listener is configured with
  `tls.RequestClientCert`, so the probe connection carries no peer
  identity. The kubelet would also have to be told to speak HTTPS and to
  skip certificate verification.
- *What about before TLS certs exist?* The listener cannot serve at all
  until its certificate source yields a certificate — exactly the
  startup window where readiness reporting matters most.

##### Pros/cons

- **Pro:** no extra port.
- **Con:** kubelet must probe HTTPS and skip verification.
- **Con:** cannot probe during the pre-certificate startup window.
- **Con:** blends an unauthenticated operational surface into an
  mTLS-only data plane.

#### C. A `health` transport plugin kind

Model health serving as another transport plugin, configured as a
`listeners[]` entry with `use: "health"`.

##### Pros/cons

- **Pro:** maximally consistent with the existing plugin architecture.
- **Con:** conflates "a transport for CKAP traffic" with "operational
  endpoints"; the `transport.Transport` contract is about serving the
  data plane.
- **Con:** heavier — a plugin registration, schema kind, and factory
  wiring — for what is a single fixed pair of endpoints.

### Enablement

#### EN-OPT. Opt-in via a non-empty address

The listener is disabled by default and enabled by setting
`monitoring.address`. An empty address (the default) binds nothing.

#### EN-DEFAULT. On by default with a fixed address

The listener binds a well-known port unless explicitly disabled.

##### Pros/cons

- EN-OPT **Pro:** khaled binds no port the operator did not ask for;
  consistent with `listeners[]`, where nothing binds unless configured.
- EN-OPT **Con:** the Helm chart must set the address explicitly (it
  does).
- EN-DEFAULT **Pro:** friendlier bare-binary default.
- EN-DEFAULT **Con:** binds a port unbidden; needs an `enabled: false`
  escape hatch, which is a second way to express "off".

### Readiness model

#### R1. Single startup gate

`/readyz` returns 200 once `server.New` has completed and 503 before.

#### R2. Subsystem-reported checks

`/readyz` aggregates a set of named checks, one per subsystem, and names
the failing ones in a `?verbose` body.

##### Pros/cons

- R1 **Pro:** trivial.
- R1 **Con:** a single boolean — no diagnostic, and nothing to report
  *during* a slow startup, which is when the signal is most wanted.
- R2 **Pro:** `/readyz?verbose` names the unfinished or unhealthy
  subsystem; works during startup; extensible.
- R2 **Con:** the readiness logic must reach into subsystem state.

#### Where the readiness logic lives (given R2)

- **R2-REG.** A `health.Registry`: each subsystem registers its own
  check.
- **R2-DERIVE.** No registry: the `server` package derives the checks by
  closing over the subsystem manager handles it already holds.

##### Pros/cons

- R2-REG **Pro:** each check sits with its subsystem.
- R2-REG **Con:** new plumbing — a registry threaded through every
  subsystem starter.
- R2-DERIVE **Pro:** no new plumbing; the `server` package already owns
  every manager handle.
- R2-DERIVE **Con:** the readiness *policy* lives in `server` rather than
  in each subsystem (the cheap state *accessors* still live with the
  subsystems).

### Shutdown sequencing

#### S-IMMEDIATE. Close listeners on shutdown signal

Tear everything down as soon as the shutdown signal arrives.

#### S-TWO-PHASE. Warn, then drain

On shutdown, flip `/readyz` to 503, wait a configurable *Shutdown
Warning Time* while CKAP listeners keep serving, then tear down — each
transport draining in-flight requests over its own *Shutdown Grace
Time*.

##### Pros/cons

- S-IMMEDIATE **Pro:** simple.
- S-IMMEDIATE **Con:** races endpoint deregistration; CKAP requests hit
  a closed socket.
- S-TWO-PHASE **Pro:** Kubernetes observes the failing `/readyz` and
  deregisters the pod before any listener closes.
- S-TWO-PHASE **Con:** lengthens shutdown by the warning time; one more
  duration knob.

## Decision

We adopt **A** (dedicated plaintext admin listener), **EN-OPT** (opt-in
via non-empty address), **R2 + R2-DERIVE** (subsystem-reported checks,
derived by the `server` package), and **S-TWO-PHASE** (warn-then-drain
shutdown).

**Probe surface — A.** Option B is disqualified by a hard technical
fact, not a preference: the kubelet cannot cleanly probe an mTLS
listener that requests a client certificate, and cannot probe it *at
all* before TLS certificates exist — which is the startup window the
readiness signal most needs to cover. C is rejected on a project value:
package contracts in khaled are kept honest and narrow (each package
documents its invariants as doc comments). The `transport.Transport`
contract is "serve the CABE data plane"; bending it to also mean
"operational endpoints" muddies that contract for a single fixed pair of
routes. A is the standard Kubernetes-ecosystem answer and the only one
that satisfies the kubelet's actual constraints.

**Enablement — EN-OPT.** khaled's existing rule, visible throughout the
config schema, is that a config block's mere presence never *does*
anything — `listeners[]` binds nothing unless populated, and YAML
configs always have every block present. EN-DEFAULT would break that
consistency and introduce a second spelling of "off" (`enabled: false`
*and* empty address). Disablement by empty address is the rule the rest
of khaled already follows.

**Readiness — R2 + R2-DERIVE.** R1's single boolean fails the first
motivating problem: it cannot say anything useful while a dependency is
hanging. R2 is required. Between R2-REG and R2-DERIVE the deciding value
is YAGNI: a registry threaded through every subsystem starter is
standing infrastructure built for an extensibility we do not yet need.
R2-DERIVE reuses handles the `server` package already holds. The honest
cost — readiness *policy* living in `server` rather than beside each
subsystem — is contained: the cheap, non-blocking state *accessors*
(`Stack.Healthy`, `Running.Ready`) still live with their subsystems and
carry their own doc comments; only the aggregation and the
include/exclude decision sit in `server`, which is exactly the package
that already knows the subsystem topology.

**Shutdown — S-TWO-PHASE.** S-IMMEDIATE leaves a real correctness gap: a
CKAP client can be routed to a pod whose listener has just closed. The
cost of S-TWO-PHASE is a bounded, configurable delay on an
already-asynchronous shutdown path. Correctness outweighs shutdown
latency here.

## Implications

### What this introduces

- A new top-level `monitoring` config block (`address`,
  `shutdownWarningTime`), registered in the config schema.
- A new subsystem package, `pkg/subsystems/monitoringsub`, owning the
  plaintext listener and the `/livez` / `/readyz` handlers.
- A new `pkg/health` package holding only the `CheckResult` vocabulary —
  deliberately logic-free.
- Cheap, non-blocking readiness accessors on existing subsystems:
  `keyserversub.Stack.Healthy`, `transportsub.Running.Ready`.
- A two-phase `server.Stop`, and the monitoring listener started first /
  stopped last in the server lifecycle.

### Naming and the renamed knob

The pre-existing, hardcoded HTTP graceful-shutdown duration is renamed
`GracefulShutdownDuration` → `ShutdownGraceTime` and exposed as
`listeners[].http.shutdownGraceTime`. This is a **source-level** rename
of an exported Go identifier. It is acceptable without a deprecation
window because `pkg/...` is khaled-internal (not a publicly committed
API surface) and the config field is *new* — no existing config used it.
The rename buys parallel terminology: `monitoring.shutdownWarningTime`
(endpoint-drain) and `listeners[].http.shutdownGraceTime`
(in-flight-request-drain) now read as the two phases they are.

### Concurrency obligation

The monitoring listener serves `/readyz` on its own goroutines from the
moment it starts — during the rest of `server.New`, and throughout
`server.Stop`. The three readiness-relevant `Server` handles
(`spiffeSrc`, `keyserverMgr`, `transports`) are therefore `atomic.Pointer`
fields. **Enduring obligation:** any future field that the readiness
closure reads must be published safely the same way; a plain field
assigned in `New` and read by `readyFunc` is a data race.

### What we have ruled out

- Probes on the CKAP listeners (B).
- A `health` transport plugin kind (C).
- A `health.Registry` (R2-REG) — *for now*. If a future plugin needs to
  contribute its own readiness check, revisiting R2-REG is the
  sanctioned path; the `health` package was deliberately kept
  logic-free so a registry can be added there without churn.

### Enduring obligations

- `monitoring.address` and `shutdownWarningTime` are read once at
  startup; the monitoring subsystem has **no reload path**. A future
  change that makes them reloadable must add one deliberately.
- The readiness check set is owned by `pkg/server/readiness.go`. Adding
  or removing a subsystem should be accompanied by a deliberate decision
  about whether it is readiness-relevant — see the FAQ on authn/claims.

### One-time obligations discharged by the implementing change

- The Helm chart enables the listener and wires `startupProbe`,
  `livenessProbe` and `readinessProbe`, all gated on a non-empty
  `monitoring.address`.
- `doc/arch/monitoring.md` and the configuration reference are updated.

### Compatibility

No migration needed. The `monitoring` block defaults to a disabled
listener, so an existing deployment that does not set
`monitoring.address` is unaffected. Behaviour is unchanged until an
operator opts in.

## FAQ

**Why is `/livez` not just an alias of `/readyz`?**
They answer different questions and drive different kubelet actions. A
failing `/livez` *restarts* the container; a failing `/readyz` *drains*
it from the Service. `/livez` in khaled is pure process-aliveness — it
always reports 200 once the process is up — because a restart only helps
a genuinely wedged process. A pod that is merely *not ready* (a slow
dependency, a config in flight) must not be restarted; that would
discard progress and could crash-loop. Conflating the two would mean
either needless restarts or no readiness draining.

**Should `/livez` ever return 503?**
Only for true process-level wedging — e.g. a detected deadlock — where a
restart is the correct remedy. khaled has no such detector today, so
`/livez` is unconditionally 200. Notably it stays 200 *during shutdown*:
a terminating pod should be drained via `/readyz`, not restarted.

**During shutdown `/readyz` reports 503 — isn't the pod still serving
CKAP traffic during the Shutdown Warning Time? Isn't 503 a lie?**
`/readyz` answers "should this pod receive *new* traffic", not "is this
pod currently serving". During the warning window the honest answer to
the former is "no" — we *want* Kubernetes to stop routing here — while
existing and in-flight requests continue to be served. The two are
consistent: 503 drives deregistration; the listener stays open so
already-routed work completes.

**Why are the authenticator and claims mapper excluded from readiness?**
Because they keep last-known-good across a failed config reload. If a
bad authn config were a readiness failure, a single fat-fingered reload
would drain every pod from the Service even though every pod is still
serving correctly with its previous config. Readiness reflects "can the
data plane serve requests", not "is every config block pristine". The
keyserver and transports are included because if *they* are broken the
pod genuinely cannot serve CKAP.

**`Stack.Healthy` only checks that the keyserver stack is constructed.
What if the keystorage DB is corrupt or its disk is full?**
`Healthy` is deliberately a cheap, non-blocking liveness read — `/readyz`
is polled every few seconds and must not do disk I/O per request. The
keystorage layer proves itself usable *at construction time* (the DB is
opened, the file lock acquired); a failure there means no `Stack` is
ever installed, so the check reports the un-built stack as not ready. A
DB that *becomes* unusable after a healthy start is not caught by this
check. That is a known, accepted limitation: if khaled later grows a
cheap cached background health signal for keystorage, `Healthy` can fold
it in without an interface change.

**`transportsub.New` binds listeners eagerly, so `Running.Ready` is
always true once `New` returns. Is the check pointless?**
It is not pointless, but its value is mostly in the *nil* case. If
`transportsub.New` fails, the manager handle is nil and `server`'s
`checkTransports` reports "not started". `Running.Ready` additionally
guards against a future transport implementation that binds lazily; it
is cheap and keeps the check honest if that assumption changes.

**Why is the monitoring listener started *first* but stopped *last* —
isn't first-in-last-out the normal teardown order anyway?**
The ordering is chosen for a specific reason, not by FILO accident. It
is started first so `/readyz` can answer — with 503 and a diagnostic —
throughout a slow startup, including while a dependency hangs. It is
stopped last so `/readyz` and `/livez` keep answering honestly across
the entire drain. If it were stopped first, a probe arriving mid-drain
would get connection-refused instead of an honest 503.

**What if `server.New` fails partway through startup?**
The monitoring listener, being started first, is already up. `Stop`
runs the partial-teardown path and closes it like everything else — it
is simply the last thing closed. During the failed-startup window
`/readyz` correctly reports 503 with the failing subsystem named.

**`monitoring.shutdownWarningTime` defaults to 5s — where does that come
from?**
When a pod enters Terminating it is removed from `EndpointSlices`
immediately; the real latency is asynchronous *propagation* (kube-proxy,
the EndpointSlice controller, ingress controllers reprogramming),
typically sub-second to ~1s but unbounded in the tail. Any consumer that
watches the readiness probe rather than the endpoint adds up to one
`periodSeconds` of detection lag. 5s covers typical propagation plus one
default probe interval while not noticeably lengthening rolling deploys.
It is also the value the Kubernetes docs' graceful-shutdown examples
use. Operators with measured tails can tune it.

**The Shutdown Warning Time is skipped when no monitoring listener is
configured. Why?**
The warning period exists so Kubernetes can observe a failing `/readyz`
and deregister the pod. With no `/readyz` there is nothing to observe,
so the wait would be pure dead time added to every shutdown. Skipping it
when `monitoring.address` is empty keeps the no-monitoring path as fast
as it was before this change.

**Is `/readyz` authenticated? Could it leak information?**
No, it is unauthenticated — it is on a plaintext listener with no authn
middleware, by design, because the kubelet cannot authenticate. The
`?verbose` body names subsystems (`keyserver`, `transports`,
`spiffe-source`) and short status strings. This is operational
topology, not secret material — no keys, no identities, no config
values. The listener should nonetheless be bound to an address reachable
only by the kubelet / cluster network, and network policy should not
expose it externally; this is the same expectation Kubernetes places on
every component's health port.

**Why a separate `pkg/health` package that contains only types?**
So the readiness *vocabulary* (`CheckResult`) is shared without forcing
a dependency direction. The monitoring listener renders `[]CheckResult`;
the `server` package produces it. Putting the type in either of those
packages would make the other depend on it for an unrelated reason.
Keeping `pkg/health` logic-free also leaves a clean home for a future
`health.Registry` should R2-REG ever be revisited.
