# Crypto-Socket Detection (Copy-Fail CVE-2026-31431 vulnerability / AF_ALG)

Podtrace can observe processes that bind **`AF_ALG`** crypto sockets, the kernel
crypto API surface exploited by **CVE-2026-31431 ("Copy-Fail")**, a Linux local
privilege escalation in the `algif_aead` module. This is **opt-in** and **off by
default**.

> **Detection, not enforcement.** Podtrace is an observer. This feature surfaces
> *use of the vulnerable interface* so you can investigate — it does not block
> the syscall, does not detect exploitation, and is not a substitute for
> patching. See [Scope & honesty](#scope--honesty) below.

## What it detects

A single tracepoint on `bind(2)` (`tp/syscalls/sys_enter_bind`) reads the
`sockaddr_alg` argument. When the address family is `AF_ALG` it emits a `CRYPTO`
event carrying:

| Field | Source | Example |
|---|---|---|
| `target` | `salg_type` | `aead`, `skcipher`, `hash` |
| `details` | `salg_name` | `gcm(aes)` |
| caller uid | `bytes` | `1000` |

The **Copy-Fail signal** specifically is an `aead` bind by an **unprivileged**
(`uid != 0`) process — that is the precondition the exploit needs (an
already-root process binding `aead` is not the privilege-escalation scenario).
Other `AF_ALG` types are still reported as general crypto observability.

## Enabling it

Add the `crypto` filter to a PodTrace / PodTraceSession / ApplicationTrace:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata:
  name: crypto-watch
  namespace: my-app
spec:
  selector:
    matchLabels: { app: my-app }
  filters: [crypto]
  exporterRef:
    name: my-otlp
```

Captured events appear like:

```
[CRYPTO] AF_ALG aead bind: gcm(aes) (uid=1000) [algif_aead by unprivileged user, Copy Fail vulnerability interface]
```

### Alerting (optional)

When alerting is configured (`PODTRACE_ALERTING_ENABLED=true` + a webhook — see
[alerting.md](alerting.md)), an `aead` bind by an unprivileged process raises a
`warning` alert that names `CVE-2026-31431` and recommends remediation. The
alert manager deduplicates and rate-limits, so a workload that legitimately
binds `aead` sockets in a loop will not flood you. No alert fires unless
alerting is enabled.

## Scope & honesty

- **Signal, not proof.** It detects the interface being used, not exploitation
  and not the kernel bug. The exploit's later page-cache writes are not
  semantically distinguishable at the syscall boundary.
- **False positives exist.** `AF_ALG`+`aead` is a legitimate kernel-crypto-offload
  API; some workloads use it. The `uid != 0` flag narrows to the
  privilege-escalation-relevant case, and the feature is opt-in for exactly this
  reason. If a workload legitimately uses it, scope the `crypto` filter away from
  that namespace.
- **Complements patching, does not replace it.** The fix is a patched kernel
  (mainline commit `a664bf3d603d`) or blacklisting the `algif_aead` module. This
  detection only shrinks the window in which you are blind to the activity.

## Future: enforce mode

Podtrace is intentionally **observer-only** today. A future BPF-LSM
`socket_bind` hook *could* deny `AF_ALG` `aead` binds outright (an enforcement
posture), but that requires `CONFIG_BPF_LSM`, puts podtrace in the syscall
denial path, and duplicates the kernel's own module blacklist. It is recorded
here as a possibility, not a commitment.

## Stability notes

- Uses the **syscall tracepoint** ABI (stable, arch-independent) rather than
  kprobes on internal symbols.
- `AF_ALG` (38) and `struct sockaddr_alg` are UAPI-stable and defined in
  podtrace's BTF-free stub, so the probe works on the embedded-stub build path
  (no kernel BTF required).
- See [ebpf-internals.md](ebpf-internals.md) for the probe-group model and
  [crd-tracerconfig.md](crd-tracerconfig.md) for how filters drive probe groups.