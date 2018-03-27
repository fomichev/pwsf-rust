Implements [V3](http://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt)
format of the https://pwsafe.org.

# Installation

```
git clone ...
rustup install nightly
rustup default nightly
cargo build
```

# Usage example

```
$ echo bogus12345 | cargo run -- -S -p ./simple.psafe3 list

$ echo bogus12345 | cargo run -- -S -p ./simple.psafe3 show "(Four|Five)"

$ cargo run -- -p ./simple.psafe3 copy "(Four|Five)"
```
