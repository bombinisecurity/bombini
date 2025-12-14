# Contribution

Welcome for contributions!

Please, **sign-off** your commits (`git commit -s`) to license your contribution under [Apache License 2.0](./LICENSE).

## Making changes

First, follow the build [guide](./docs/src/getting_started/build.md) and make sure that project is successfully build
and development environment is properly configured.

### Update Detector's configs

[config.proto](./proto/config.proto) is used to define configs for detectors.
After making changes to proto file generate the code:

```
cargo xtask proto-gen
```

### Linting

Use `cargo fmt` and `cargo clippy` to check your changes:

```bash
cargo clippy --workspace --all-features -- -D warnings
cargo fmt --all -- --check
cd bombini-detectors-ebpf
cargo clippy --workspace --all-features -- -D warnings
cargo fmt --all -- --check
```

These checks can be performed automatically during commit using [pre-commit](https://pre-commit.com/).
Once the package is installed, simply run `pre-commit install` to enable the hooks, the checks will run automatically before the commit becomes effective.

**Note**: Please, do not stage `vmlinux.rs` file in commit.

## Running Tests

After making changes check if tests are passing:

```bash
cargo xtask test --release
```

To add new tests, please, follow test writing [guide](./bombini/tests/README.md).

### Updating Documentation

If you make changes to Bombini configuration yaml files or events. The documentation must be updated.
Please, follow the documentation [guide](./docs/README.md).
