# Third-Party Software

## Tricky Addon - Update Target List

The embedded Oh My Keymint WebUI contains adapted source from
[KOWX712/Tricky-Addon-Update-Target-List](https://github.com/KOWX712/Tricky-Addon-Update-Target-List)
at commit
[`cf167849aaa7696972a3c7826ec94294e9e47fce`](https://github.com/KOWX712/Tricky-Addon-Update-Target-List/commit/cf167849aaa7696972a3c7826ec94294e9e47fce).

That source is licensed under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

The adapted source supplies the offline package-selection portion of the Oh My
Keymint WebUI. It reads and replaces the OMK `scoop` list through the native
`inject` helper. That adapted portion does not provide network access, module
self-update, property modification, trust editing, or automatic WebUI-host
installation. Oh My Keymint separately provides a keybox action that validates
and atomically installs a local XML file, plus a security-patch action that
downloads Google's official Android Security Bulletin and updates only the four
`[trust]` patch-level fields. Its separate restore action resets those fields
to `auto` without network access.

## Native HTTPS bulletin client

The security-patch WebUI action uses the Rust
[ureq](https://github.com/algesten/ureq) HTTP client (version 3.4.0), licensed
under the MIT or Apache License 2.0. Its HTTPS implementation uses
[rustls](https://github.com/rustls/rustls) and
[rustls-webpki](https://github.com/rustls/webpki), licensed under their
Apache-2.0/ISC/MIT and ISC terms respectively, together with
[webpki-roots](https://github.com/rustls/webpki-roots), licensed under
CDLA-Permissive-2.0. These dependencies are built into the existing `keymint`
helper; no device-provided `curl` or `wget` is used.
