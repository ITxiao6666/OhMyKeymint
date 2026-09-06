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
and atomically installs a local XML file. Its security-patch action downloads
Google's official Android Security Bulletin, updates the four `[trust]`
patch-level fields, applies the selected date to both runtime security-patch
properties with `resetprop`, and records the original values for restore. Its
separate restore action restores those properties and resets the four fields to
`auto` without network access.

## Pixel PIF profile feed

The WebUI's PIF fingerprint field mapping follows the documented
Build-variable contract from
[TrickyStore](https://github.com/5ec1cff/TrickyStore/tree/master#build-vars-spoofing).
The field contract was checked against TrickyStore commit
[`3a515c5fe1ce4c94d5424305afe2eaf4812a635d`](https://github.com/5ec1cff/TrickyStore/commit/3a515c5fe1ce4c94d5424305afe2eaf4812a635d).
No TrickyStore code or binary is included in or required by Oh My Keymint.

Pixel model names and PIF profile values are downloaded at runtime from the
`bot` branch of
[KOWX712/PlayIntegrityFix](https://github.com/KOWX712/PlayIntegrityFix). The
feed format and generation path were checked against its `inject_s` commit
[`2f8199a90a150ad98921438608e1e0e951ba2d5f`](https://github.com/KOWX712/PlayIntegrityFix/commit/2f8199a90a150ad98921438608e1e0e951ba2d5f).
That project is licensed under GPL-3.0. Oh My Keymint does not copy or execute
its WebUI or Autopif implementation; it independently validates the generated
`device_list.json` and `device_prop/*.prop` data protocol before rendering the
OMK PIF profile.

## Specter interface and Widevine workflow reference

The WebUI information architecture and the vendor Widevine provisioning
workflow were checked against
[dpejoh/specter](https://github.com/dpejoh/specter) commit
[`829c4fa95ab5a08e4cd7e18dd686e73896d90a24`](https://github.com/dpejoh/specter/commit/829c4fa95ab5a08e4cd7e18dd686e73896d90a24).
That project is licensed under GPL-3.0. Oh My Keymint does not include or run
Specter's WebUI or shell scripts. Its WebUI and Rust implementation are
independent; they reproduce only the documented interaction with the fixed
attestation feed and the vendor `KmInstallKeybox` command contract.

The Widevine action downloads its server-managed attestation document from
`https://rawbin.dpejoh.com/clips/attestation`. The document is not bundled with
Oh My Keymint. OMK restricts the request to that exact HTTPS host and path,
validates the decoded XML envelope, and attempts to delete its temporary copy
after the vendor command exits, reporting cleanup failures.

## Native HTTPS client

The security-patch, PIF fingerprint, and Widevine WebUI actions use the Rust
[ureq](https://github.com/algesten/ureq) HTTP client (version 3.4.0), licensed
under the MIT or Apache License 2.0. Its HTTPS implementation uses
[rustls](https://github.com/rustls/rustls) and
[rustls-webpki](https://github.com/rustls/webpki), licensed under their
Apache-2.0/ISC/MIT and ISC terms respectively, together with
[webpki-roots](https://github.com/rustls/webpki-roots), licensed under
CDLA-Permissive-2.0. These dependencies are built into the existing `keymint`
helper; no device-provided `curl` or `wget` is used. Each action has a separate
exact host and path allowlist, and redirects are validated before another
request is made.
