# Updating Documentation

Docs is manually updated. When you make changes in `proto/config.proto` then `docs/src/configuration/reference.md` must be regenerated.
Install `protoc` and `protoc-gen-doc`:

```bash
curl -L -o protoc-gen-doc.tar.gz https://github.com/pseudomuto/protoc-gen-doc/releases/download/v1.5.1/protoc-gen-doc_1.5.1_linux_amd64.tar.gz
tar -xzf protoc-gen-doc.tar.gz
chmod +x protoc-gen-doc
sudo mv protoc-gen-doc /usr/local/bin/
```

Generate `reference.md`:

```bash
cargo xtask docs-gen
```