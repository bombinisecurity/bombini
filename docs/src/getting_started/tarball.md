# Tarball

You can get a tarball with installation scripts for bombini systemd service:

```bash
wget https://github.com/bombinisecurity/bombini/releases/download/v1.1.0/bombini-v1.1.0.tar.gz
```

## Install / Uninstall

Unpack bombini tarball:

```bash
tar -xvf bombini-v1.1.0.tar.gz
```

If you need config customization then update detector configs in `bombini/usr/local/lib/bombini/config`.
Then run install script:

```bash
sudo ./bombini/install.sh
```

Check events:

```bash
tail -f /var/log/bombini/bombini.log
```

Uninstall with uninstall.sh:

```bash
sudo ./bombini/uninstall.sh
```
