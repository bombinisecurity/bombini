# Compatibility

Bombini supports the following Linux kernel versions: **6.2, 6,8 and 6.14**.
However, it might work on all 6+ kernels.

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