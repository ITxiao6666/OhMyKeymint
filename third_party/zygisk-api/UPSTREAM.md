# Vendored source

This directory vendors `rmnscnce/zygisk-api-rs` at commit
`457585fa8fa32d8c394ec45ae411cc36d2711680`.

The crate is licensed under the Zero-Clause BSD (0BSD) license. The source is
kept local so Android builds do not depend on a live Git checkout. The
upstream `src/aux.rs` file is named `src/aux_mod.rs` here because `aux.rs` is a
reserved filename on Windows; `src/lib.rs` contains the corresponding module
rename and exports remain unchanged.
