# @messager/ratchet

Forward-secret sessions between two users: the Double Ratchet with one-time
prekeys, as implemented by [vodozemac](https://github.com/matrix-org/vodozemac)
(Matrix's Olm implementation, independently audited by Least Authority).

**No cryptography is written in this package.**

| Folder | What it is |
|---|---|
| `rust/` | A thin wrapper that exposes vodozemac to JavaScript. Every function is a direct call into the library. |
| `wasm/` | The compiled output of `rust/`. Committed, so nobody needs Rust or Docker to run the tests. |
| `src/` | A small typed TypeScript surface over `wasm/`, and the tests. |

## The compiled file is checked against its source

`wasm/` is a binary nobody can review by reading it, so CI rebuilds it from
`rust/` on every pull request and fails if the result differs by a single
byte from what is committed. That works because the build is reproducible:
the Rust image, every crate (`rust/Cargo.lock`), the `wasm-bindgen` tool and
the CPU architecture the compiler runs on are all pinned in `build.sh`.

## Changing the wrapper or upgrading vodozemac

Needs Docker and nothing else.

```
npm run build:wasm -w @messager/ratchet
```

Commit the changed `rust/` and `wasm/` files together. Upgrading vodozemac
means changing its exact version in `rust/Cargo.toml`, running
`cargo update -p vodozemac` (or deleting `rust/Cargo.lock` to regenerate
it), reading the upstream changelog, and rebuilding.

## Choices made here

- **Session version 1** (an 8-byte message authentication tag), which is
  vodozemac's default and the configuration that was audited. The
  full-length variant is behind an "experimental" flag upstream.
- **libolm compatibility is compiled out.** This project never used libolm.
- **Saved state is always encrypted** under a 32-byte key supplied by the
  caller. That key lives next to the data in the browser, so this guards
  against accidental disclosure, not against someone with access to the
  device.

## Licences

vodozemac is Apache-2.0. The compiled module also contains its Rust
dependencies, which are under Apache-2.0, MIT or BSD-style licences; the
exact set and versions are listed in `rust/Cargo.lock`.
