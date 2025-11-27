# GTFObins

GTFOBins detector detects [GTFOBins](https://gtfobins.github.io/) execution.
It checks if privileged shell is executed and returns process information about GTFOBins
binary that is spawning the shell.

## Required Linux Kernel Version

6.8 or greater

## Config Description

Config represents the list of GTFOBins filenames.

```yaml
enforce: true
gtfobins:    # https://gtfobins.github.io/#+shell%20+SUID%20+Sudo
  - aa-exec
  - awk
  - busctl
  - busybox
  - cabal
...
```

When enforce flag is set true execution of GTFOBins is blocked. False is by default.