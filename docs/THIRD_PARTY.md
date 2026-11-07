# Third-Party Software

## miuix-vue WebUI components

The embedded WebUI is built with the Vue 3 components from
[YuKongA/miuix-vue](https://github.com/YuKongA/miuix-vue), version `0.1.1`.
The library is licensed under the Apache License 2.0. Oh My Keymint uses its
navigation bar, top app bar, cards, preferences, sheets, dialogs, progress
indicators, and icons; application behavior and native bridge calls remain in
the Oh My Keymint source.

## Monet color generation

The WebUI bundles Google's [Material Color Utilities](https://github.com/material-foundation/material-color-utilities),
version `0.4.0`, under the Apache License 2.0. It supplies HCT palette generation
and the 2021/2025 color specifications; UI components remain miuix-vue.
The MIUIX role mapping in `webui/src/appearance.ts` is adapted from
[compose-miuix-ui/miuix MonetMapping.kt](https://github.com/compose-miuix-ui/miuix/blob/26b37993ce6073ac7cab9b986ab57352c126dc81/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/theme/MonetMapping.kt),
copyright 2025 compose-miuix-ui contributors, licensed under Apache-2.0.
System seed selection and the accent choices follow
[KernelSU's theme implementation](https://github.com/tiann/KernelSU/tree/85cab5f841b55bed180c10dfdbe33f876aba7820/manager/app/src/main/java/me/weishu/kernelsu/ui/theme).

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
feed format, launch-SDK contract, and native property-area behavior follow
[`v4.9-inject-s`](https://github.com/KOWX712/PlayIntegrityFix/releases/tag/v4.9-inject-s),
commit [`9ad24d23ccbb24ff5acde6d77905dee9711b14ca`](https://github.com/KOWX712/PlayIntegrityFix/commit/9ad24d23ccbb24ff5acde6d77905dee9711b14ca).
That project is licensed under GPL-3.0. Oh My Keymint does not copy or execute
its WebUI or Autopif implementation; it independently validates the generated
`device_list.json` and `device_prop/*.prop` data protocol before rendering the
OMK PIF profile. Its Rust process-private property-area implementation adapts
the behavior of upstream `zygisk/src/main/cpp/property_virtualizer.cpp`, including
lazy-area warmup, inline-value handling, and rollback. This third-party-derived
portion remains subject to GPL-3.0. No upstream C++ library, DEX provider, or
signature-spoofing payload is bundled. OMK retains its own validated hook fallback
and does not apply upstream ADB/USB property overrides.

The Java launch-SDK field type was checked against the configuration and Java
field contracts in
[osm0sis/PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork/tree/bfad5ecb068dd8ba84af7ea6b48b8c50dbc34441),
commit `bfad5ecb068dd8ba84af7ea6b48b8c50dbc34441` (GPL-3.0). OMK implements
the integer field update in its existing Rust/JNI payload without copying Fork
code. The independent Play Store Build option follows KOWX712 `v4.9-inject-s`'s
`spoofVendingBuild` contract: it applies the complete profile string field set,
not just the fingerprint, and does not change either SDK integer or native
properties. No provider, signature, or Play Store SDK spoofing implementation
is bundled.

The long-property layout and legacy-reader behavior are checked against AOSP
bionic's Android 17
[`prop_info`](https://android.googlesource.com/platform/bionic/+/refs/heads/android17-release/libc/system_properties/include/system_properties/prop_info.h),
[`prop_info` constructors](https://android.googlesource.com/platform/bionic/+/refs/heads/android17-release/libc/system_properties/prop_info.cpp),
and [`SystemProperties` readers](https://android.googlesource.com/platform/bionic/+/refs/heads/android17-release/libc/system_properties/system_properties.cpp).
The derived `Build.TYPE` flags are checked against AOSP `Build.java` in
[Android 12](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android12-release/core/java/android/os/Build.java)
and [Android 17](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/core/java/android/os/Build.java).
These are ABI and field-contract references; the implementation remains Rust
and does not bundle framework or libc binaries. Source-contract checks do not
constitute runtime validation on each Android release.

## Google attestation status snapshot

The module includes the public JSON snapshot used to seed the local
`/data/misc/keystore/omk/data/google_attestation_status.json` cache on a first
install. Later successful HTTPS responses from Google's fixed attestation
endpoint replace that cache atomically after the complete response passes the
same schema and serial validation used for live checks. The snapshot contains
only Google's public `REVOKED`/`SUSPENDED` entries; it does not contain private
keys or device identifiers.

## Specter interface reference

The WebUI information architecture was checked against
[dpejoh/specter](https://github.com/dpejoh/specter) commit
[`829c4fa95ab5a08e4cd7e18dd686e73896d90a24`](https://github.com/dpejoh/specter/commit/829c4fa95ab5a08e4cd7e18dd686e73896d90a24).
That project is licensed under GPL-3.0. Oh My Keymint does not include or run
Specter's WebUI or shell scripts. Its WebUI and Rust implementation are
independent.

## Vendor RKP repair

The optional **Fix RKP** action references the fixed vendor-tool invocation in
[jiyin004-jpg/ommega](https://github.com/jiyin004-jpg/ommega/blob/c6172dc553543aa8eea1b7e03cd50c2ff6f1efb1/a-side/source/template/webroot/index.html#L1471),
licensed under AGPL-3.0-or-later. OMK implements the command in Rust with an
explicit persistent-write confirmation and uses only the device's existing
`/vendor/bin/KmInstallKeybox`. No upstream vendor executable, shell function,
Keybox material or RKP CSR-format change is included. The output is a vendor
tool completion report, not proof of successful Google provisioning.

## Local device RKP issuer

The local RKP protocol, CBOR/DICE verification, native KeymasterUtils ABI and
V1 Java bridge are adapted from
[eltavine/Duck-ToolBox](https://github.com/eltavine/Duck-ToolBox/tree/75f78866071287ecc749dcbbf53dbd2fc47b4e67)
including optional CSR fingerprint metadata from
`75f78866071287ecc749dcbbf53dbd2fc47b4e67` (MIT).
Relevant upstream paths are `crates/duck-rkp-device/src/` and
`crates/duck-rkp/src/{cbor,verify}`. The V1 PureSoft MAC/AIDL construction also
derives from `LazyBonesLZY/rkp-v1-oracle` revision `b28480c` (MIT), as credited
by Duck. Both notices are shipped in
`template/THIRD_PARTY_LICENSES/Duck-ToolBox.txt` and `rkp-v1-oracle.txt`.
OMK's implementation is in `src/local_rkp/`, `src/rkp_v1_bridge.rs`,
`src/local_rkp_artifacts.rs` and `runtime/rkp/RkpV1Bridge.java`.

OMK retains the device-backed V2 native, V1 AIDL and V1 native request paths.
Native paths are enabled only when Qualcomm SoC evidence is present; MediaTek
devices use the vendor-independent V1 AIDL bridge. The bridge discovers both
`rkpdapp.apk` and `rkpdapp.google.apk` in the system RKP APEX.
It provides explicit issuance/import confirmations, private OMK-local storage,
bounded fixed-endpoint HTTP requests and strict issued-chain validation using
OMK's existing Google root pins. It does not copy Duck's simulated-device
issuance, seed/identity storage, arbitrary endpoint selection or automatic
import behavior. The Java bridge contains no network or private-key logic.

## SOTER local identities and CPU-ID overrides

The EngineerMode gen_unique_id policy rule is adapted from Andrea-lyz/ommega
commit 9583e028449f8d2c5cfef97f6f86d42aa840c738 (AGPL-3.0-or-later),
by Yunzhe Liao / Andrea-lyz. It grants only the engineering app domain the
existing unique-ID attestation permission; it does not bypass KeyMint checks.

The native HAL hook and local state machine derive from Ommega
(AGPL-3.0-or-later), including c6172dc553543aa8eea1b7e03cd50c2ff6f1efb1.
The local random identity policy references Andrea-lyz/ommega commits
4721358e and 55e7dec9, reviewed through
9583e028 (master on November 5, 2026). Each local identity owns random CPU-ID
and signing material. OMK uses its existing BoringSSL Rust interfaces.

Per-application CPU-ID mapping and support for both 32 and 36 hex characters
are adapted from the user-provided tricky-soter-service-1.9.2 source,
soter/src/hook/soter_local.rs and soter/src/local_support.rs, under
AGPL-3.0-or-later. OMK resolves package/user policy in the privileged broker,
keeps new files in its private data directory, and does not copy the source's
factory-key imports, C++ host, preference deletion or
remote forwarding. Attribution is shipped in
THIRD_PARTY_LICENSES/SOTER-local.txt.

The app-local Oplus EngineerMode cryptoeng display hook references
host/module.cpp in the same user-provided source (AGPL-3.0-or-later). OMK
implements it in Rust inside the existing Zygisk payload, without a new
companion protocol or native runtime component. It synthesizes the selected
engineering display response only; it does not provision hardware keys.

The optional app-local Java status bridge uses LSPlant (LGPL-3.0-or-later),
revision 06bd3412d639d6b0d76fe6c7388066fe44e8963d, and its pinned DexBuilder
and parallel-hashmap sources. The native inline backend is the upstream
LSPlant test dependency io.github.vvb2060.ndk:dobby:1.2 (Apache-2.0), with
org.lsposed.libcxx:libcxx:30.0.16248370 (Apache-2.0 WITH LLVM-exception).
scripts/build_engineer_bridge.py pins source revisions and archive SHA-256
digests. Dependencies are cached under target and are never fetched on-device.
The generated callback and C++ glue only replace the selected engineering
application's display result, not hardware-key state or attestation validation.

## Native HTTPS client

The security-patch and PIF fingerprint WebUI actions use the Rust
[ureq](https://github.com/algesten/ureq) HTTP client (version 3.4.0), licensed
under the MIT or Apache License 2.0. Its HTTPS implementation uses
[rustls](https://github.com/rustls/rustls) and
[rustls-webpki](https://github.com/rustls/webpki), licensed under their
Apache-2.0/ISC/MIT and ISC terms respectively, together with
[webpki-roots](https://github.com/rustls/webpki-roots), licensed under
CDLA-Permissive-2.0. These dependencies are built into the existing `keymint`
helper; no device-provided `curl` or `wget` is used. The security-patch and PIF
actions each have a separate exact host and path allowlist, and redirects are
validated before another request is made.
