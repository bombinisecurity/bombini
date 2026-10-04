# Examples

Start with [quickstart](quickstart/README.md): a complete config directory with a script
that triggers every rule. The other files are single detector configs, each named
`<detector>-<topic>.yaml`.

| Example | Demonstrates | Trigger |
|---|---|---|
| [quickstart](quickstart) | Detection and in-kernel blocking with procmon, filemon and netmon | `./examples/quickstart/trigger.sh` |
| [filemon-rules.yaml](filemon-rules.yaml) | Several rules on one hook, `scope` by binary name and path prefix | `tail /etc/passwd`, `cat /etc/hosts` |
| [filemon-macros.yaml](filemon-macros.yaml) | Reusable `lists` and `macros` in rules | `cat /etc/passwd` from an interactive `bash` |
| [netmon-egress-outside-local.yaml](netmon-egress-outside-local.yaml) | TCP connections outside private networks, CIDR matching with `in` | `curl -sI https://example.com` |
| [procmon-privilege-raise.yaml](procmon-privilege-raise.yaml) | Privilege changes: setuid to root, capset, user namespace creation | `sudo true`, `unshare -U true` |
| [procmon-gtfobins.yaml](procmon-gtfobins.yaml) | Sandbox mode: blocks root shells spawned by [GTFOBins](https://gtfobins.github.io) | `sudo find . -exec /bin/sh \; -quit` fails with `Operation not permitted` |

## Run an example

The quickstart directory already enables procmon, filemon and netmon, so any example can
replace the config of its detector there. For example, from the repository root:

```bash
cp -r examples/quickstart /tmp/bombini-example
cp examples/filemon-rules.yaml /tmp/bombini-example/filemon.yaml
docker run --pid=host --rm -it --privileged \
  -v /tmp/bombini-example:/usr/local/lib/bombini/config:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/bombinisecurity/bombini:v1.1.0
```

Then run the trigger from the table in another terminal. Rule syntax is described in
[Rules](https://bombinisecurity.github.io/bombini/configuration/rules.html).

Unit tests check that every example parses and its rules compile: `cargo test -- rule`.
