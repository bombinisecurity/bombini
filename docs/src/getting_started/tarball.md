# Tarball

You can get a tarball with installation scripts for bombini systemd service:

```bash
wget https://github.com/bombinisecurity/bombini/releases/download/v1.0.0/bombini-v1.0.0.tar.gz
```

## Install / Uninstall

Unpack bombini tarball:

```bash
tar -xvf ./target/bombini.tar.gz -C ./target
```

If you need config customization then update detector configs in `target/bombini/usr/local/lib/bombini/config`.
Then run install script:

```bash
sudo ./target/bombini/install.sh
```

Check events:

```bash
tail -f /var/log/bombini/bombini.log
```

Uninstall with uninstall.sh:

```bash
sudo ./target/bombini/uninstall.sh
```