**What this changes and why**

**How it was tested**
- [ ] `node --test "test/*.test.js"` (and with `KREVO_NO_WASM=1` if it touches cryptography)
- [ ] `cd rust/krevod && cargo test` (if it touches consensus, cryptography or the Rust node)

**Consensus impact**
<!-- None / describe it. A consensus change must land in the JavaScript node AND the Rust node, with test vectors. -->
