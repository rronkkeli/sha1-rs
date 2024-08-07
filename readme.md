This is my implementation of SHA-1. This project's goal was to learn how Secure Hash Algorithm and its successors work and how to implement them using rust.

Comparison hash for test.txt was generated with a tool shipped with 7-zip and for test strings a web tool was used.

## Example usage

Put lib.rs into a directory in your src. In this example the directory is named sha1.

Into your Cargo.toml you need to add the following:

```toml
[lib]
name = "sha1"
path = "src/sha1/lib.rs"
```

And into your code files that use this library, you need to add:

```rs
use sha1::*;
```

This library implements trait `HashSHA1` for Strings, primitive strings, byte vectors, arrays and slices so you can call method sha1() for them directly.

```rs
// Simple main.rs example
use sha1::*;

fn main() {
    // Produces a lower case hexadecimal hash string from str "Testimerkkijono"
    let hash: String = "Testimerkkijono".sha1().to_lhex();

    println!("{hash}");
}
```