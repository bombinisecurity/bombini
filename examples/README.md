# Examples

* [quickstart](quickstart/README.md) — a complete config directory with a script that
  triggers every rule. Start here to see Bombini running.
* [rules](rules/) — a rule library: ready-made policies grouped by detector, based on the
  [Falco](https://github.com/falcosecurity/rules) default rules and
  [Tetragon](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy) tracing
  policies, plus rules that only Bombini can express.
* The single-topic configs below, each named `<detector>-<topic>.yaml`, show one feature at
  a time.

## Rule library

The [rules](rules/) directory holds one file per detector, named `<detector>.yaml`, so it
can be used as a config directory as-is.

The rules are not a one-to-one port. Bombini has no container, tty or command-line fields
outside the exec sandbox, so each rule is *based on* a Falco or Tetragon rule and rewritten
in terms of what Bombini sees: binary and parent names, paths, flags, capabilities and
addresses. The comment above each rule says what it detects and gives the ATT&CK
technique. Some rules have no counterpart in either project: they use in-kernel blocking,
parent lineage or the agent's own pinned maps.

| Pack | Covers |
|---|---|
| [procmon.yaml](rules/procmon.yaml) | Shells spawned by servers, GTFOBins escapes, exec from `/tmp` and `/dev/shm`, setuid/setgid to root, capability raises, user namespaces, user management tools, ptrace, non-shell children of sshd, shells exec'd into containers, `rm -rf /` |
| [filemon.yaml](rules/filemon.yaml) | Credential and SSH key access, `authorized_keys` writes, log tampering, cron and shell startup persistence, setuid bits, executable mappings from writable paths, writes to `core_pattern`/`modprobe`/`uevent_helper`, `/etc/ld.so.preload`, tampering with Bombini's pinned maps |
| [netmon.yaml](rules/netmon.yaml) | Egress outside the private network, cloud metadata, mining pools, ssh on non-standard ports, raw and packet sockets |
| [kernelmon.yaml](rules/kernelmon.yaml) | eBPF programs loaded or accessed by tools that are not known agents |

### Audit by default

Every hook that supports a sandbox ships with `sandbox.enabled: false`: matching events
are reported with `"blocked":false` and nothing is denied. To enforce a hook, flip its
`sandbox.enabled` to `true`; with `deny_list: true` the rules of that hook are blocked in
the kernel and everything else is allowed. Run in audit mode first and check the events
for legitimate matches before switching.

Two exceptions:

* `procmon.sched_process_exec` exists only to block (it kills the process) and ignores
  `sandbox.enabled`, so the hook as a whole is `enabled: false`.
* `netmon.egress`/`ingress` and all of `kernelmon` have no sandbox mode; they only report.

## Single-topic configs

| Example | Demonstrates | Trigger |
|---|---|---|
| [filemon-rules.yaml](filemon-rules.yaml) | Several rules on one hook, `scope` by binary name and path prefix | `tail /etc/passwd`, `cat /etc/hosts` |
| [filemon-macros.yaml](filemon-macros.yaml) | Reusable `lists` and `macros` in rules | `cat /etc/passwd` from an interactive `bash` |
| [netmon-egress-outside-local.yaml](netmon-egress-outside-local.yaml) | TCP connections outside private networks, CIDR matching with `in` | `curl -sI https://example.com` |
| [procmon-privilege-raise.yaml](procmon-privilege-raise.yaml) | Privilege changes: setuid to root, capset, user namespace creation | `sudo true`, `unshare -U true` |
| [procmon-gtfobins.yaml](procmon-gtfobins.yaml) | Sandbox mode: blocks root shells spawned by [GTFOBins](https://gtfobins.github.io) | `sudo find . -exec /bin/sh \; -quit` fails with `Operation not permitted` |

## Run an example

The quickstart directory already enables procmon, filemon and netmon, so any single-topic
config can replace the config of its detector there. From the repository root:

```bash
cp -r examples/quickstart /tmp/bombini-example
cp examples/filemon-rules.yaml /tmp/bombini-example/filemon.yaml
docker run --pid=host --rm -it --privileged \
  -v /tmp/bombini-example:/usr/local/lib/bombini/config:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/bombinisecurity/bombini:v1.2.0
```

Then run the trigger from the table in another terminal. For the rule library, copy the
packs you want over the quickstart configs and add the matching detector to
`config.yaml`. Rules can also be checked without root and without loading anything into
the kernel:

```bash
bombini --validate examples/rules/filemon.yaml
```

Rule syntax is described in [Rules](https://bombinisecurity.github.io/bombini/configuration/rules.html).

Unit tests check that every example parses and its rules compile: `cargo test -- rule`.
They walk both `examples/` and `examples/rules/`, and name the detector after the part of
the file name before the first `-`.
