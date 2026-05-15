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

## Running Tests

After making changes check if tests are passing:

```bash
cargo xtask test --release
```

To add new tests, please, follow test writing [guide](./bombini/tests/README.md).

### Updating Documentation

If you make changes to Bombini configuration yaml files or events. The documentation must be updated.
Please, follow the documentation [guide](./docs/README.md).

# CO-RE Support

Bombini uses a two-layer CO-RE system to read
kernel struct fields portably across kernel versions

## Pipeline

* shim.c              -> clang (BPF target) -> shim.o
* shim.c              -> bindgen            -> src/co_re/gen.rs
* src/co_re/core_*.rs -> safe Rust wrappers over gen.rs

## Adding a new kernel struct

1. Define the struct and its shims in `src/co_re/c/shim.c`

Add the struct with `__attribute__((preserve_access_index))` and apply the appropriate macro to each field you need:

| Macro | Use case |
|---|---|
| `SHIM(struct, member)` | Scalar field |
| `SHIM_REF(struct, member)` | Take address of field (nested struct by value) |
| `SHIM_BITFIELD(struct, member)` | Bitfield |
| `SHIM_WITH_NAME(struct, member, alias)` | Field whose C name would clash |
| `ARRAY_SHIM(struct, member)` | Array - returns pointer to first element |
| `ARRAY_SHIM_WITH_NAME(struct, member, alias)` | Array with alias |
| `SHIM_TRUSTED(struct, member)` | Trusted pointer (no null check by verifier) |
| `SHIM_TRUSTED_OR_NULL(struct, member)` | Trusted-or-null pointer |

Example — adding `struct foo`:

```c
struct foo {
    int  bar;
    struct baz *child;
    unsigned char name[16];
} __attribute__((preserve_access_index));

SHIM(foo, bar);
SHIM_TRUSTED(foo, child);
ARRAY_SHIM(foo, name);
```

If a field's type doesn't exist in `types.h`, add a minimal typedef there.

2. Create `src/co_re/core_foo.rs`

Map each generated shim to a Rust method using the matching macro:

| shim.c macro | Rust macro |
|---|---|
| `SHIM` | `rust_shim_kernel_impl!` |
| `SHIM_REF` | `rust_shim_kernel_impl!` |
| `SHIM_TRUSTED` | `rust_shim_kernel_trusted_impl!` |
| `SHIM_TRUSTED_OR_NULL` | `rust_shim_kernel_trusted_or_null_impl!` |
| pointer/address return | `rust_shim_kernel_impl_ptr!` |

```rust
use super::r#gen::{self, *};
use super::{CoRe, rust_shim_kernel_impl, rust_shim_kernel_trusted_impl};

#[allow(non_camel_case_types)]
pub type foo = CoRe<r#gen::foo>;

impl foo {
    rust_shim_kernel_impl!(pub, foo, bar, i32);
    rust_shim_kernel_trusted_impl!(pub, child, foo, child, baz);  // fn name differs from field
    rust_shim_kernel_impl!(pub, foo, name, *mut u8);
}
```

Macro signature reference:

```rust
// simple: derives fn name from member name
rust_shim_kernel_impl!(pub, StructName, member, ReturnType);

// explicit fn name (needed when member name would clash or is recast):
rust_shim_kernel_trusted_impl!(pub, fn_name, StructName, member, ReturnType);
```

All methods return `Option<ReturnType>` and are `unsafe`.

3. Export from `src/co_re.rs`

```rust
mod core_foo;
pub use core_foo::*;
```

4. Use in eBPF programs via `core_read_kernel!`

```rust
let bar = core_read_kernel!(foo_ptr, bar).ok_or(0i32)?;

// Chained traversal — each step returns Option, short-circuits on None:
let name = core_read_kernel!(foo_ptr, child, name).ok_or(0i32)?;
```

5. Rebuild generated bindings

`gen.rs` is generated every time `shim.c` or `types.h` is modified.