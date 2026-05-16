# Monitoring: `/livez` and `/readyz`

khaled exposes Kubernetes-style liveness and readiness probes on a
dedicated plaintext HTTP listener — the *monitoring listener*. This
document describes how that listener fits into the server architecture.
It is the maintained architecture reference; the original decision
record is `doc/plans/2026-05-16-monitoring-livez-readyz-design.md`.

## Why a separate listener

khaled's data plane is the CKAP transport: an mTLS listener that
requests a client certificate and serves CKAP over TLS 1.3. Kubelet
HTTP-GET probes present no client certificate, and the listener cannot
be probed before its TLS certificate source has produced a certificate.
Mounting the probes there would also blend an unauthenticated
operational surface into an mTLS-only data plane.

The monitoring listener is therefore separate and plaintext, carrying
only `/livez` and `/readyz` — the same data-plane / operational-plane
split made by kube-apiserver, etcd and the controller-manager.

## Configuration

The listener is configured by the top-level `monitoring` block and is
**opt-in**: it is enabled by a non-empty `monitoring.address` and
disabled (the default) by an empty one. Config is YAML, so the block is
always present; presence alone enables nothing.

```yaml
monitoring:
  address: "0.0.0.0:8081"   # empty (default) => listener disabled
  shutdownWarningTime: "5s" # endpoint-drain delay; default "5s"
```

`monitoring.address` and `shutdownWarningTime` are read once at startup.
Like `listeners[]`, changes require a restart; the monitoring subsystem
has no reload path.

## Probe semantics

`/livez` always reports `200 OK` once the process is up. Liveness in
khaled is pure process-aliveness: a kubelet restart only helps a wedged
process, so `/livez` never consults subsystem state and never flips to
`503` — not even during shutdown, because a terminating pod should be
drained, not restarted.

`/readyz` reports `200` when every readiness check passes and `503`
otherwise. `/readyz?verbose` adds a plaintext body, one `[+]`/`[-]` line
per check plus a summary, mirroring kube-apiserver's `/readyz?verbose`.

Non-GET requests to a known path get `405`; unknown paths get `404`.

### Readiness checks

The set of checks is owned by `pkg/server` (`readiness.go`), which
closes over its subsystem manager handles. `pkg/subsystems/monitoringsub`
only renders the result. The current checks:

- `spiffe-source` — the shared SPIFFE source has produced a usable
  certificate. When no SPIFFE source is configured this passes
  trivially.
- `keyserver` — the keyserver stack (keystorage, key schedule, server)
  is fully constructed. This is a cheap non-blocking read; it does no
  I/O, because a store that failed to open leaves no stack at all.
- `transports` — every CKAP listener is bound.

A subsystem that has not started yet — early in startup, or after a
failed partial startup — reports a failing `not started` check rather
than panicking. This is what makes `/readyz` informative during a slow
startup.

The authenticator and the claims mapper are deliberately **excluded**.
They keep last-known-good across a failed config reload, so a bad authn
or claims config must not drain a pod that is still serving. Readiness
reflects whether the data plane can serve CKAP requests, not whether
every config block is pristine.

## Lifecycle: started first, stopped last

The monitoring listener is started **first** in `server.New`, before any
data-plane subsystem. The readiness closure it is given reads manager
handles that are still nil; the closure is null-safe and reports them as
`not started`. So a slow or hung dependency (for example an
unreachable SPIFFE Workload API) surfaces as `/readyz` stuck at `503`
with a diagnostic body — a `startupProbe` fails cleanly instead of
hitting a blind connection-refused.

It is correspondingly stopped **last** in `server.Stop`, so `/livez` and
`/readyz` answer honestly across the whole shutdown drain.

## Shutdown sequencing

`server.Stop` is two-phase. The terminology parallels the per-listener
`listeners[].http.shutdownGraceTime`:

```
  t
  v_______________________
  |
  | Shutdown Warning Time (SWT)   monitoring.shutdownWarningTime
  | /readyz = 503
  |_______________________
  |
  | Shutdown Grace Time (SGT)     listeners[].http.shutdownGraceTime
  | transport listeners closed, in-flight requests drained
  | /readyz = 503
  |_______________________

  Shutdown Total Time = SWT + SGT
```

1. **Flip readiness.** `Stop` sets an internal `shuttingDown` flag.
   `/readyz` checks it before the per-subsystem checks and returns
   `503` for the rest of the drain regardless of subsystem state.
   `/livez` stays `200`.

2. **Shutdown Warning Time.** If the monitoring listener is active and
   `shutdownWarningTime > 0`, `Stop` sleeps that long. CKAP listeners
   keep serving; Kubernetes observes the failing `/readyz` and removes
   the pod from the Service's EndpointSlices. With no monitoring
   listener this phase is skipped — there is nothing for Kubernetes to
   observe, so the wait would be dead time.

3. **Shutdown Grace Time.** Subsystems are torn down in reverse
   dependency order. Closing a transport drains its in-flight requests
   over that listener's own `shutdownGraceTime`.

4. **Monitoring last.** The monitoring listener closes last.

## Kubernetes wiring

The in-tree Helm chart enables the listener and wires all three probe
kinds to it (`startupProbe`, `livenessProbe`, `readinessProbe`),
gated on a non-empty `monitoring.address`. `startupProbe` against
`/livez` tolerates a slow first start; `livenessProbe` against `/livez`
restarts a wedged process; `readinessProbe` against `/readyz` drains the
pod from the Service whenever a subsystem is not ready.
