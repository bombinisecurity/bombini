# GTFObins

The BprmCheck hook can be used to detect the execution of [GTFOBins](https://gtfobins.github.io/).
It checks if privileged shell is executed and returns process information about GTFOBins
binary that is spawning the shell.

## Config Description

Scope predicate represents the list of GTFOBins filenames.
Event predicate represents the list of possible shell filenames and checks if the executing process is running as root.

```yaml
bprm_check:
  enabled: true
  sandbox:
    enabled: true
    deny_list: true
  rules:
  - rule: GTFOBins  # https://gtfobins.github.io/#+shell%20+SUID%20+Sudo
    scope: binary_name in
      [
        "aa-exec",
        "awk",
        "busctl",
        "busybox",
        ...
      ]
    event: name in ["sh", "bash", "dash", "zsh"] AND euid == 0
```

When sandbox deny_list mode is set true execution of GTFOBins is blocked.