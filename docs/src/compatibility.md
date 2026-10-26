# Compatibility

Bombini supports the following Linux kernel versions: **6.2, 6.8, 6.14 and 7.0**.
However, it might work on any kernel starting from 6.2.

## Requirements    

Before run, check if LSM BPF is enabled on your system.

```
cat /sys/kernel/security/lsm
```

if there is `bpf` in the output, than BPF LSM is enabled.
Otherwise, you have to enable it adding this line to `/etc/default/grub`:

```
GRUB_CMDLINE_LINUX="lsm=[previous lsm modules],bpf"
```

Update grub and reboot the system.

BTF information must be provided by your Linux kernel. Check if btf file exists:

```
ls -la /sys/kernel/btf/vmlinux
```

## Kubernetes

[Pod enrichment](configuration/k8s.md) supports Kubernetes **1.32** and newer.
The shipped manifests use `flowcontrol.apiserver.k8s.io/v1`, available since 1.29,
and the agent gets its initial pod list as a streaming watch list, which is enabled
by default since 1.32.