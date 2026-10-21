# Configuration Guide

OhMyKeymint (OMK) uses two active configuration files:

- `/data/misc/keystore/omk/config.toml` controls the KeyMint service, the
  identity it reports, and the secrets used for OMK-created keys.
- `/data/misc/keystore/omk/injector.toml` selects which apps use OMK and which
  KeyStore requests are routed to it.

This guide describes the active configuration used by the current build. The
examples are followed by a separate field-by-field reference so that the short
comments in the examples are not the only explanation.

**Jump to:** [`config.toml`](#configtoml) | [`injector.toml`](#injectortoml)

## Before editing

For ordinary use, the only setting that normally needs changing is `scoop` in
`injector.toml`. Keep the safety filters, all `[intercept]` switches, and the
generated `[crypto]` values unchanged.

Before making a change:

1. Make a private backup of both active files.
2. Edit the files under `/data/misc/keystore/omk/`, not copies in the module ZIP.
3. Keep ordinary strings inside quotes and booleans as `true` or `false`. Keep
   the `scoop = [` and `]` lines, then add one bare package name per line;
   those entries omit both quotes and commas.
4. Change one thing at a time, save the complete file, and check the matching
   log after the change.

Never publish `[crypto]` values, IMEI, IMEI2, MEID, serial numbers, or an
unredacted copy of either active file.

## How changes are loaded

Both components watch their active file for valid changes. Their behavior is
not identical:

- A valid `injector.toml` is applied to new requests without a reboot.
- A valid `config.toml` is read automatically. The four patch-level fields,
  biometric compatibility switch, and three TA delay ranges can take full
  effect without restarting keymint. The field reference below states when a
  restart is required.
- A malformed file saved while its component is running is rejected and the
  last valid in-memory configuration remains active.
- A malformed `config.toml` present when keymint starts prevents keymint from
  starting. Fix the file and restart keymint.
- A malformed `injector.toml` present when the injector starts leaves OMK
  request routing disabled. Saving a valid file lets the watcher restore
  routing automatically; restart the injector only if it does not recover.
- If either file is missing when its component starts, OMK creates a new file
  with generated defaults. This is not a safe way to reset a working setup:
  regenerated secrets do not restore keys protected by the previous secrets.
The restart commands are documented in
[Restarting keymint and injector](../README.md#restarting-keymint-and-injector).
After changing app routing, close and reopen the affected app to avoid mixing
an already-open operation with the new route. If a process restart is needed
for a clean boundary, restart the injector only. An injector-only setting
change does not require a keymint restart.

## Limited-use keys

Keystore-enforced limited-use keys reserve one remaining use for each active
operation. New operations cannot exceed the current durable count. Successful
finish commits the count before returning output; abort, pruning, terminal
backend errors, and dropped operations release their reservation without
consuming a use. Reservations stay in memory and are independent of runtime
configuration reloads. Rebinding an alias creates a separate key entry and
does not transfer reservations from the old entry.

Wrapped-key imports reserve a Keystore-enforced use of the wrapping key until
the destination key is saved. The durable decrement and destination alias
publication share one database transaction. A failed import or save leaves the
remaining count and previous aliases intact. Successful final consumption
removes the wrapping key; replacing that same alias publishes the imported key
atomically. TA-enforced single-use wrapping keys consume their secure-deletion
slot after a successful unwrap import. Failed unwraps retain that slot. The TA
consumption precedes database publication, so a later database failure does not
restore a TA-enforced use.

Key generation and imports delete unpublished TA key blobs on a best-effort
basis when storage or publication fails. Cleanup failure does not replace the
original operation error.

## App patch-level profiles

Optional `config.toml` profiles set the patch levels reported and bound into
keys generated or imported by selected applications:

```toml
[app_patch_levels."com.example.app@0"]
os_patchlevel = "2026-04-05"
vendor_patchlevel = "2026-04-05"
boot_patchlevel = "2026-04-05"
```

A bare package target applies to every Android user; `package@user_id` applies
to one user and takes precedence over the bare target for that package. Each
field may be omitted or set to `"auto"` to inherit the current global value.
OS and vendor fields accept exact calendar dates in `YYYY-MM-DD` form that
are not in the future. The boot field also accepts a decimal `u32` wire value.
An explicit empty profile inherits all global fields and takes precedence over
a bare profile. Invalid targets, fields, or values reject the complete candidate.

The current caller's packages select the profile without consulting a key,
alias, or keyblob's origin. Native service UIDs use the global patch levels
without an application package lookup. Packages sharing one UID also share the selected
profile; conflicting effective profiles among matched packages return
`INVALID_ARGUMENT`. The profile controls generated/imported key
characteristics, the signed attestation extension, keyblob validation, and
upgrade. It does not change which backend handles a request. The TA's global
HAL and boot state remain unchanged. Each operation retains the profile
selected at begin, including after a configuration reload; new requests use
the new configuration. Changing a profile follows the normal OMK keyblob
validation and upgrade rules for existing keys.

## Embedded WebUI

The module includes a WebUI for selecting packages in `scoop`, installing a
local keybox, managing global Android security patch levels, applying a Pixel
PIF fingerprint through OMK's own Zygisk payload, and independently enabling
Tencent Soter compatibility (Beta). Open it from the Oh My Keymint module page in
KernelSU. With Magisk, open an installed KSUWebUIStandalone or WebUI X host and
select Oh My Keymint; the module does not install either host.

The main package picker shows user applications only. System applications,
including Android overlays, are managed through **More > Add system apps**.
Classification uses Android's package-manager list even when the WebUI host
cannot provide an application's label or metadata. Hiding system applications
from the main list does not remove their saved routing selections.

The home page loads its status and diagnostics without enumerating installed
applications; package discovery starts when the package picker opens. Dialogs
present their loading state before querying the device. Long device, language,
and file lists mount in stages, and closing a panel discards pending read results.
The PIF device catalog loads only when fingerprint spoofing is selected in its
panel; inspecting a disabled profile does not download the catalog. Loading
panels reserve their content space while the opening animation runs.
Navigation drags are coalesced to display frames without repeated layout reads.
Certificate presentation is cached until its source snapshot changes, and a
diagnostic refresh retains the current rows while it loads. System-color refreshes
reuse an unchanged palette and update only changed color overrides.

The Settings page keeps the selected language, theme mode, accent, and visual
effects in the WebUI's local storage. Language selection opens a height-limited
MIUIX bottom sheet with single-choice rows, including the system-language option.
The list scrolls inside the sheet; dismissing it or navigating back leaves the
current selection unchanged. When Monet is enabled, **Default** reads
the current Android user's resolved dynamic primary colors from system resources,
including wallpaper overlays, for both light and dark mode. Colors refresh on
opening the WebUI, returning to the foreground, and system theme changes.
Android 14 and newer use named primary roles; Android 12-13 use the equivalent
accent palette tones. A fixed accent supplies a custom seed instead.
The selected palette style and color standard generate the full MIUIX palette
using Material Color Utilities and MIUIX's role mapping, including neutral
unchecked controls and themed surfaces. Rainbow and FruitSalad use SPEC_2021,
as SPEC_2025 does not define those styles. If system colors cannot be read,
the current session retains its last resolved colors, or uses the static MIUIX
palette when none are available. No wallpaper data or new persistent cache is created.
Turning Monet off restores the static MIUIX light/dark palette while remembering
the selected accent for the next time Monet is enabled. Bar blur, floating
navigation, and liquid glass are optional and remain disabled until selected;
each option is independent; liquid glass only affects the floating navigation
surface and does not enable floating navigation by itself.
The bottom navigation stays anchored above the host's bottom safe area while
pages switch and restore their own scroll positions. Interface scaling changes
the bar's size without scaling the host's safe-area spacing. Top and side
safe areas also retain their physical size at every interface scale. Scroll
clearance follows the actual navigation height and bottom offset, so the last
item can be scrolled fully above the bar.
With blurred non-floating navigation, its bottom gesture safe area also paints
the navigation surface: blurred when supported, otherwise opaque.
This safe-area surface is not scaled with the navigation controls.

Native status and navigation bar icons are controlled by the WebUI host.
The WebUI enables edge-to-edge layout and extends its surface behind the system
bars when the host and content use matching light/dark modes. When the modes
differ, the system safe areas use the host surface from
`/internal/colors.css` to preserve icon contrast. Hosts without this endpoint
use the WebView's system color preference for this fallback. System bars remain
visible; this does not change the host or Android theme settings.
Blurred non-floating navigation keeps its own surface through the bottom
gesture area so there is no contrasting strip below the navigation controls.

The Home page reads each identity item independently. The Keybox card parses
the installed XML and checks the private key against its leaf certificate
without rewriting the file. Source classification also verifies every
leaf-to-issuer signature link in leaf-to-root order. A chain is recognized as a
Google key only when that verification reaches a final certificate with one
of Google's pinned attestation-root public keys. The supported RSA root and
the newer EC attestation root are pinned separately. A verified chain ending
in one of these roots is shown as a Google hardware key when its root-adjacent
certificate Subject contains the factory `serialNumber` attribute. It is shown
as a Google remote key when it carries the RKP ProvisioningInfo extension or
its root-adjacent certificate identifies `CN=Droid CA2, O=Google LLC`. A chain
without either verified provisioning marker is shown as unknown. The root's key
algorithm and certificate name are not used to infer the provisioning source.
When a Keybox contains multiple algorithm chains, every chain must resolve to
the same known source; an unknown or conflicting chain makes the Keybox source
unknown. The Home page shows only this source classification. The hardware
level is read from the leaf certificate Subject organization (`O=TEE` or
`O=StrongBox`) and shown separately as **Security Level**. Older factory
keyboxes that use the X.520 title attribute (`T=TEE` or
`T=StrongBox`) are supported as a compatibility fallback. Valid chains that
do not match either source or level are shown as unknown. The
security-patch card reads the current
`ro.build.version.security_patch` runtime property. **TEE: Normal** is shown
only after the injector reaches OMK and obtains the Trusted Environment
security level. The spoofed-device value is the Pixel model in OMK's active PIF
profile; it describes the configured target and is not a separate live check of
a Google Play services process.

The Keybox card checks every certificate serial number from both presented
algorithm chains against Google's attestation status list at
`https://android.googleapis.com/attestation/status`. A validated local cache
is used for up to 12 hours after its last successful refresh; the next status
check after that interval performs an online lookup. A successful online
lookup is atomically cached at
`/data/misc/keystore/omk/data/google_attestation_status.json`. If the endpoint
cannot be reached, the WebUI uses that locally validated cache; a first install
is seeded from the validated snapshot shipped in the module. A lookup is shown
as **Not revoked** when no serial is present. If any serial has a Google status
of `SUSPENDED` or `REVOKED`, the card shows **Revoked**. A network, HTTP,
certificate-parsing, or response-parsing failure is never treated as
**Not revoked** when neither local source is valid. The cache and bundled
snapshot contain public Google data and can become stale, so **Not revoked**
does not prove that Play Integrity will accept the Keybox. When a refresh is
due, an unavailable endpoint falls back to the last validated cache and then
the bundled snapshot.

The WebUI does not display or clear a recent-activity history. Existing activity
files from older installations are ignored by the current interface.

The Home page exposes read-only runtime diagnostics for OMK KeyMint,
Soter, the registered TEE and StrongBox KeyMint services, and the matching
`default` and `strongbox` RKP Binder services. A missing
optional StrongBox service is shown as unregistered. These checks do not issue
an attestation challenge, contact an RKP provisioning server, or certify
hardware-backed operation. A vendor KeyMint process is not used as evidence
that OMK itself is running. The Keybox inspector shows public
certificate-chain metadata (algorithm and chain length) and each certificate's
subject, validity dates, and serial number without exposing private
keys or relay credentials. The expandable chain view presents the root first,
uses the current interface language for date formatting, and keeps dates in
UTC. A diagnostic read failure is reported in the UI and does not change runtime
routing.

The injector daemon waits for keystore2 to appear and retries injection after
startup or a process restart. If keystore2 disappears before launcher discovery,
the launcher returns a retryable failure to the existing daemon loop.

The WebUI can read and replace the `scoop` package list and can install a local
keybox selected through Android's system document picker. The picker can use
any installed storage provider, including MT Manager, and requests all MIME
types so providers that label XML as `text/plain` or `application/octet-stream`
remain available; the WebUI still requires an `.xml` filename. If the system
picker cannot be opened, the WebUI falls back to its shared-storage browser.
Its **Sync security
patch** action uses the root WebUI bridge to make an HTTPS request to the
official `https://source.android.com/docs/security/bulletin/asb-overview` page,
falling back to Google's official Chinese mirror when the primary host is
unavailable. It extracts the newest published security-patch level and uses
that level's year and month. When the saved default
`ro.build.version.security_patch` has day `01`, the synchronized date also has
day `01`; otherwise it keeps the published Google date. The saved system date
is authoritative if it differs from the saved vendor date. The action updates
the four `[trust]` patch-level fields and uses `resetprop -n` to set both
`ro.build.version.security_patch` and `ro.vendor.build.security_patch` to that
date without going through Android's property service or triggering its change
actions. The same `-n` mode applies to restore, rollback, and startup writes;
unrelated property writes keep their existing behavior. Before the first sync,
the native helper saves the current values of both
properties to
`/data/misc/keystore/omk/data/security_patch_defaults.toml`. A later sync keeps
the existing snapshot instead of replacing the saved defaults.

The action uses the module's native HTTPS client with embedded WebPKI roots;
the device does not need to provide `curl` or `wget`. HTTPS redirects are
accepted only when the final URL remains the official bulletin page. A failed
request, unrecognized page, invalid date, or snapshot write leaves the
configuration and properties unchanged. The native helper verifies both
property writes and rolls them back when the paired update or subsequent
configuration write fails. **Restore default security patch** makes no network
request. It first restores both properties from the snapshot, then sets
`security_patch`, `os_patchlevel`, `vendor_patchlevel`, and `boot_patchlevel` to
`"auto"`. It deletes the snapshot only after both property restores and the
configuration update succeed; a failed restore retains it for another attempt.
The two properties are global Android runtime state for the current boot, so
every process that reads them can observe the synchronized or restored values.

When Oh My Keymint is uninstalled from KernelSU, the bundled uninstaller removes
exactly `/data/adb/omk` and `/data/misc/keystore/omk`. This includes the active
configuration, keybox, logs, and OMK-created key data and cannot be undone. A
module disable does not remove these directories; reboot after an uninstall.

The **Spoof PIF fingerprint** action is a separate OMK Zygisk integration. It
downloads a Pixel device list from
`KOWX712/PlayIntegrityFix`'s `bot/device_list.json`, then downloads the selected
`bot/device_prop/<product>.prop`. The upstream bot refreshes these records
daily from Google's Android preview pages, Android Flash Tool Canary metadata,
and Pixel security bulletin. The helper first tries the exact GitHub Raw path
and then the exact jsDelivr path. It does not run the upstream Autopif shell
script and does not require a device-provided `curl`, `wget`, or shell download
tool.

The native helper accepts only the fixed feed paths, validates every catalog
entry, requires `FINGERPRINT`, `MANUFACTURER`, `MODEL`, and `SECURITY_PATCH`
in a profile, and accepts optional `DEVICE_INITIAL_SDK_INT` launch-SDK metadata
as a positive 32-bit decimal integer. Unknown keys, duplicate keys, and missing
required fields are rejected. The launch-SDK metadata is retained in the profile;
when absent, the product's initial API level defaults to `32`, following
PlayIntegrityFix `v4.9-inject-s`. Native property spoofing uses that value for
`ro.product.first_api_level` and `32` for `ro.board.first_api_level`, without
overriding other API-level properties. GMS Build spoofing writes the same
launch-SDK value to the integer `Build.VERSION.DEVICE_INITIAL_SDK_INT` field.
It does not change `Build.VERSION.SDK_INT`.
When Java Build spoofing is enabled, `Build.IS_ENG`, `Build.IS_USERDEBUG`,
and `Build.IS_USER` are synchronized with the selected `Build.TYPE`. All
written strings, type flags, and the GMS launch SDK are read back before the
payload reports a verified Java update. A failed JNI operation is logged and
its pending exception is cleared; an exception already pending before the
update is preserved and the update is skipped. Java writes are sequential;
on failure, fields already written remain applied and the payload does not
report a verified update.
The helper splits the fingerprint into its eight Build components. It stores
the following values in canonical JSON only after they agree
with one another and satisfy TrickyStore's value limits:

```text
MANUFACTURER=Google
MODEL=Pixel ...
FINGERPRINT=google/.../...:.../.../...:user/release-keys
BRAND=google
PRODUCT=...
DEVICE=...
RELEASE=...
ID=...
INCREMENTAL=...
TYPE=user
TAGS=release-keys
SECURITY_PATCH=YYYY-MM-DD
```

The complete candidate is atomically stored at
`/data/misc/keystore/omk/data/pif_fingerprint.json`; an invalid download or
failed write leaves the previous profile unchanged. The WebUI controls Java
Build spoofing and native property spoofing independently for Google Play
services through **Spoof Build** and **Spoof Props**; both default to on.
A separate **Spoof Build (Play Store)** switch defaults to off and applies all
12 string fields listed above and the three derived type flags inside the Play
Store, including model, product, device, fingerprint, release, build ID, and
security patch. It does not change the store's launch SDK, running SDK, or
native properties, and is independent
of the two GMS switches. All three switches can be enabled together.
Changes take effect only after Apply succeeds. Turning off the main switch
removes the profile. The profile uses schema version 2; canonical version-1
profiles remain readable without a rewrite and default to both paths enabled.
The optional `spoof_vending_build` boolean defaults to false and is omitted
from canonical JSON when false. Profiles without this option leave Play Store
spoofing disabled.
Version-2 profiles require the matching Zygisk payload; reboot after installing
an updated module before applying the new options.
This state file is not part of either OMK TOML schema. OMK packages its own
Zygisk library, which reads
the validated profile through its root companion when a new
`com.google.android.gms.unstable` or `com.android.vending` process (including a
named `:...` child process) is specialized by the Zygisk Next loader. During
pre-app specialization, when native spoofing is enabled for GMS, the payload warms up
bionic's lazily opened property areas before inspecting their mappings. It
attempts validated process-private property-area replacement; shared property
files and other processes are not modified. Read-only values of 92 bytes or
more use bionic's long-property layout within the existing profile limit of
126 bytes. Storage is reused or allocated within the private mapping, retaining
property addresses. Installation verifies full callback values, names, serial
metadata, legacy API results, and mapping identity. Legacy APIs with a 92-byte
buffer return bionic's standard long-property message; callers must use
`__system_property_read_callback` to obtain the complete value. The hook
fallback uses the same legacy representation and resolves the full property
name even when the legacy caller omits its name buffer or receives a truncated
name. The fallback preserves bionic's serial change token; only the private-area
path changes the stored property metadata. If the private mapping lacks
space, has an unsupported layout, or fails installation or readback, the payload
restores any replaced mappings and uses the existing property hooks.
On AArch64 the callback hook is attempted only after validating the wrapper
semantics, memory mappings, and BTI/MTE permissions. A rejected
callback hook leaves libc unchanged, records the reason, and continues with
the available PLT and Java paths. After specialization the payload updates Java
`Build` fields and the integer launch SDK only when GMS Build spoofing is enabled,
and probes 14 core identity and launch-API properties through the callback API
when GMS native spoofing is enabled, logging mismatches and missing properties.
Store processes are separated before native hook installation and receive
only the optional Java Build strings and derived type flags. A process with
no enabled spoofing path unloads the PIF library. OMK retains its own Google-process scope and
does not include upstream provider/signature spoofing or ADB/USB overrides.
The WebUI shows the selected fingerprint, patch date, initial API level, and
saved options. Its desktop development preview uses labelled in-memory sample
data, not Android state or a Play Integrity result. Zygisk Next must already be
installed and enabled by the user; OMK does
not bundle, install, or implement that loader. The helper ends both target
process families after a successful change so a later process receives the
selected values. Disabling spoofing removes the profile and repeats the same
process refresh. The spoof is process-local: it does not call `resetprop`,
change global Android properties, or change values under OMK's `[device]`
section.

**Fix Tencent Soter Server (Testing)** is an optional software test implementation
of the D-soter Binder reply contract. Its switch is disabled by default and is
independent of PIF, `scoop`,
and all KeyMint routing and key storage. Applying the switch atomically stores
one strict `0` or `1` byte in
`/data/misc/keystore/omk/data/soter_beta.conf`. Opening or cancelling the dialog
does not write this file. The native commands are `--webui-get-soter-beta` and
`--webui-set-soter-beta 0|1`; both run as short-lived root helpers without
starting the daemon. Read failures are reported to the WebUI, and the payload
does not enable the experiment when configuration cannot be validated. Tencent
Soter Beta, per-app remote Soter and global Qualcomm Soter HAL takeover are
mutually exclusive; disable the active service before enabling another mode.
Install and enable Zygisk Next separately. Changing this switch terminates
existing exact-name `com.tencent.soter.soterserver` processes after saving, so
Android can rebind with the selected mode. No device reboot, package force-stop
or key deletion is performed. If a process cannot be terminated, the helper
reports that the preference was saved but service refresh failed; restart the
service before relying on the new mode. Compatibility is not verified.

**Per-app remote Soter** uses the existing Soter panel and the application
settings sheet in **Add package names**. Enable **Take over SOTER for selected
apps** and **Enable remote Soter relay**, save the relay settings, then enable
**Take over remote SOTER** separately for each intended application. An entry is
an exact `package@Android-user` target. Ordinary OMK target selection,
recommendations and automatic package addition do not opt an app into Soter.
All switches default to off; saving an app selection does not enable a master
switch. Remote KeyMint, Keybox forwarding and PathMask are not included.

The Rust Zygisk hook requires Zygisk Next and the Tencent SoterServer AIDL
service. It routes only opted-in callers at the SoterServer entry point using
the kernel Binder caller UID. Unselected transactions retain their original
target, cookie and payload. Version and biometric-capability queries retain
the native implementation. The Qualcomm HAL is not stopped or replaced in
per-app mode; global HAL takeover remains a separate compatibility mode.
Switching from global takeover requires confirmation that the software HAL
has stopped and the stock HAL is running before per-app mode is published.
Changing the global or per-app master mode then refreshes SoterServer so a
running host cannot retain the previously selected injection mode. Ordinary
relay-parameter and app-selection saves do not restart the host.

App selections share the existing protected `remote.conf` as `app_enabled`
and a JSON-array `app_targets` field. The native delta command
`--webui-set-soter-app-target-base64` changes one exact target without changing
relay settings or restarting services. Configuration writes serialize on the
existing directory; saving an older relay dialog retains newer app selections.
The root Zygisk companion rereads policy and Android's package table for each
request. Shared UIDs, isolated UIDs and unresolved packages are not opted in.
Credentials and network requests stay in that companion, not in the injected
app process; private inherited channels create no persistent socket or UID file.

The Tencent SDK's default UID argument `0` is not caller identity. Remote key
slots are chosen from the authenticated caller UID, followed by the explicit
UID mapping, rather than granting authority to an arbitrary request argument.
Signing sessions are bounded, expire and are bound to the caller and relay
configuration. Remote failures do not fall back to local fixture keys or
successful native replies. The remote device's TEE and biometric checks remain
authoritative; this feature does not manufacture fingerprint authentication.
An already-running SoterServer must first load the updated Zygisk library.
If its companion channel is lost, restart SoterServer to apply new selections;
previously selected calls fail rather than silently changing key backends.

**Global Soter HAL compatibility mode** is a separate Qualcomm integration for
`vendor.qti.hardware.soter.ISoter/default`. Its WebUI panel exposes independent
switches for enabling the software TA and its remote Soter relay. Enabling the
software TA takes over the vendor HAL. With the relay disabled, supported
operations use the local ledger; with the relay enabled, they use the configured
server. The panel also exposes editable relay URL, B device
ID, token, and optional UID mapping fields, plus a switch to accept self-signed
TLS certificates. Existing nonempty relay identity values are preserved; empty
URL, B device ID, or token fields are filled with their built-in defaults when
saved. Both switches are disabled by default, TLS certificate validation
remains enabled unless explicitly disabled, and the default UID map is empty.
Opening or cancelling the panel does not write configuration. The software TA
cannot be enabled while Tencent Soter Beta is enabled. Relay preferences and
parameters can be saved while the software TA is disabled, including while
Tencent Soter Beta is enabled; saving these preferences does not take over the
vendor HAL. An enabled relay requires a valid HTTP or HTTPS URL, device ID, and
token even when the software TA is disabled.

Saving atomically writes the relay fields to
`/data/misc/keystore/omk/data/soterta/remote.conf` with mode `0600`, using the
`remote_enabled=` key. The independent software TA flag is stored in
`/data/misc/keystore/omk/data/soterta/enabled`. Built-in credentials are part of
the module and are not secret storage; custom saved configuration is device-local.
When both switches are enabled, supported operations use the configured relay;
relay failures return the stock dead-TA reply and never fall back to local
material. A relay response requesting `local_only` is also a failure, not
permission to switch the slot to another key identity. The relay does not cache
ASK/AuthKey read results, so deletion and regeneration are visible immediately.
For requests carrying an application UID, it reads Android's existing
`/data/system/packages.list` and sends a uniquely resolved package as
`caller_pkg` with `caller_pkg_src=arg`. This is an untrusted request-argument
hint, not authenticated Binder identity. Resolution uses the source UID before
relay UID mapping; profiles share the Android app-ID mapping. Missing tables,
unknown packages, system/isolated UIDs and ambiguous shared UIDs omit the hint.
It creates no persistent package table and does not infer a package from the
foreground application or a key alias.
Disabling only the relay keeps the software TA active with its local
ledger. Disabling the software TA restores the stock HAL and retains the relay
preferences. The service is independent
of KeyMint routing, and saved settings
survive reboot. Saving through the native bridge also asks the installed
`soterta.sh` watchdog to converge immediately; its normal service loop continues
to publish takeover status in `status.json`.
After each new software TA instance successfully takes over the service name,
the watchdog terminates existing `com.tencent.soter.soterserver` processes so
Android clients can reconnect without a stale HAL proxy. Ordinary watchdog
polls do not restart the host. This does not force-stop WeChat, delete its
preferences, clear Soter keys, or reboot the device.
The WebUI sends configuration as one bounded Base64-encoded UTF-8 JSON argument
to `--webui-set-soter-hal-base64`, then reads `--webui-get-soter-hal` and checks
every field before reporting a successful save. The raw JSON command
`--webui-set-soter-hal` remains available for correctly quoted direct CLI calls.

**Clear GMS cache** is a one-shot action, not a persistent switch. The root
helper `--webui-clear-gms-cache` removes only the contents of `cache` and
`code_cache` for `com.google.android.gms` and `com.android.vending` under
`/data/user/<user>` and `/data/user_de/<user>`. It preserves the directories and
their metadata, databases, preferences, accounts, files and other app data.
Only Android's explicit `/data/user/0` to `/data/data` alias is accepted;
app/cache directory symlinks cannot redirect deletion outside the selected
cache. External-storage caches and other applications are not cleared.
The helper then executes `killall -v com.google.android.gms.unstable` and
`killall -v com.android.vending`, including after a partial cleanup failure.
Absent processes are not an error; Android may restart stopped processes.
The WebUI reports partial failures rather than claiming successful cleanup.
It never invokes `pm clear` or resets Google app data. No new persistent
configuration, backup or log file is created by this action.

**Fix RKP** is an explicitly confirmed vendor provisioning action, not an
OMK RKP-service replacement. `--webui-repair-rkp --confirm-persistent-write`
requires root and runs only the device's root-owned, executable
`/vendor/bin/KmInstallKeybox` with the fixed placeholder arguments
`Keybox_file Device_ID true rkp`. `LD_LIBRARY_PATH` is set to
`/vendor/lib64:/vendor/lib64/hw` for that child only. No real Keybox is supplied,
no tool is downloaded or bundled, and permissions are not changed.
The vendor tool may write persist/TEE provisioning state; its behavior varies
by device, and rollback is not guaranteed even after an error or timeout.
The WebUI therefore requires a separate risk confirmation for every execution.
Execution is bounded to 120 seconds and 16 KiB of output, with no automatic
retry. Only a successful exit with an upstream completion marker is reported
as tool completion. This does not verify Google certificate provisioning,
factory diagnostics, hardware attestation or fingerprint payment. Do not use
it on a healthy device or repeat it blindly. Browser previews execute neither
maintenance action.

The `soterta-svc` Binder entry point, request parsing, reply encoding and relay
logic are implemented in Rust. It accepts both the standard 14-method and
compact 11-method Soter transaction layouts. Each request is resolved from its
complete argument payload, with bounded strings and no shared first-call layout
guess. Payloads that do not fully match a supported operation are rejected before
dispatch. A truncated request that is itself a complete valid request under the
other layout is indistinguishable at this boundary. Standard Parcelable replies
are the default; only a Binder caller whose process basename is exactly
`cryptoeng` receives the native buffer layout. This process-name check selects
serialization only, not authorization. Interface version and hash replies retain
the vendor contract. Dead and log modes do not create local state.
With the local biometric gate enabled, an unreadable or timed-out fingerprint
counter or boot clock refuses signing with `-26`; only explicit `--bio-gate=off`
disables this evidence requirement. This userspace counter is not TEE-backed
biometric authentication. Remote operations retain the B-side TEE's checks.

Repeated remote ASK generation returning `-5` is treated as successful only when
fresh `has_ask` and `export_ask` reads confirm a present key in the same mapped
UID slot. The export must contain a complete key document, public key, matching
UID, CPU ID, counter and RSA signature tail. These checks validate structure,
not hardware provenance or signature trust. Failed confirmation preserves the
original `-5`. The request and its confirmations share a 20-second budget;
HTTP redirects are not followed. No key is deleted or regenerated by this
confirmation path.

The relay forwards Soter only, not Keybox or KeyMint data.

For both Zygisk Soter modes, the entry point selects only the exact
`com.tencent.soter.soterserver` process. A supplied nonempty app data directory
must belong to that package; loaders which omit it are supported. The separate
Rust handler intercepts both Binder transaction and security-context transaction
commands. It matches codes 1 through 13 and the UTF-16
`com.tencent.soter.soterserver.ISoterService` descriptor, following D-soter.
The handler parses the required UID, alias, challenge and session arguments
using bounded Parcel reads. Software test mode permits unused OEM trailing
fields; remote mode requires the supported complete request layout. Driver
buffer and request sizes remain bounded to 1 MiB. Matching selected requests go to a
local Binder stub; unrecognized transactions remain unchanged. Other processes,
including Google Play and KeyMint, do not install this handler.

Zygisk registers the native hook before specialization. The local Binder stub
is created and interception is activated after specialization, once Android
has established the app's identity and file-descriptor state.

Android 13 and newer use the NDK legacy-interface option to let the Rust
handler match the descriptor independently of the Parcel header layout.
Android 12/12L retain the platform's standard AIDL interface-header check;
nonstandard headerless requests are not supported on those versions.
All 13 upstream reply contracts are implemented: ASK and auth-key creation,
export, existence and removal; signing sessions and signature results; device
ID, version, and extra parameters. ASK and auth-key presence are maintained
per UID and alias in process memory. Removing a key changes subsequent
existence and export results. Key presence, counters and sessions reset when
Tencent SoterServer restarts; this feature creates no persistent key storage.

The RSA-2048 key is the publicly available RustCrypto `rsa` 0.9.10 test fixture,
not a device key or a secret. Its matching public key is derived from that
fixture. The fixed test CPU ID is the 16-byte ASCII value `OMK-SOFT-TEST-01`,
represented as `4f4d4b2d534f46542d544553542d3031` in exported JSON. Key exports
use the shared length-prefixed JSON codec and an RSA-PSS/SHA-256 signature with
a 20-byte salt. Signatures are generated over each exported JSON body, including
the requested UID, a positive monotonically increasing per-UID counter, and
the auth-key alias where applicable. Exports identify this implementation with
`software_test: true` and `key_source: "public_test_fixture"`.

Signing sessions have distinct IDs and use a bounded in-memory table. No
fingerprint capability is provided: `finishSign` returns `-26` and empty data
for an available session, or `-1000` for an unknown or consumed session. Extra
fingerprint parameters return a present parcelable with a null value rather
than a fabricated sensor type or position.

Diagnostics use the `OhMyKeymint-Soter` logcat tag. Loading, disabled state,
companion failures and hook installation are logged separately. Each method
logs its first intercepted request and first delivered simulated reply, or
first reply failure, per process. Arguments, key data and challenges are not
logged. To inspect an affected device after rebooting and invoking its Soter
client, run `adb logcat -d -s OhMyKeymint-Soter:I`. An installation message alone
does not establish that requests reached the handler.

The exported signatures are valid only under the publicly known software test
key. They do not establish hardware key provenance, authorize fingerprints,
repair payments, or supply Play Integrity verdicts. Real TEE, KeyMint and
vendor HAL paths remain unchanged. Saving a switch confirms only that the
preference was saved, not that device compatibility was verified. The feature
is experimental; no supported-OS-wide validation is implied. Disabling and
rebooting restores the unmodified Soter process path.

All other WebUI assets are bundled and no network request is made for normal
local operations. None of the WebUI network paths requires a device-provided
`curl` or `wget`.

The WebUI does not parse or rewrite `injector.toml` itself. It sends caller
targets to the native `inject` helper. The helper first parses the current complete
file, normalizes duplicates, surrounding whitespace, and decimal identifiers,
rejects invalid targets and TrickyStore-style `!` or `?` suffixes, then renders and atomically
replaces the complete file while preserving its ownership and mode. A read,
parse, validation, or write failure is returned to the WebUI and leaves the
existing file unchanged. Saving remains disabled when the current list could
not be loaded.

A successful save triggers the same injector hot-reload path as a valid manual
edit. It applies to new requests without restarting keymint. Close and reopen
the affected app when a clean routing boundary is required.

For a keybox installation, the native `keymint` helper enforces the input size
limit, decodes the selected file as UTF-8, and runs the complete in-memory
`KeyBox` validation, including private-key and certificate-chain matching. Only
then does it atomically replace the canonical lowercase
`/data/misc/keystore/omk/keybox.xml`. A read, size, UTF-8, validation, or write
failure leaves the active keybox unchanged. The keybox watcher loads a
successful replacement automatically, so a restart is normally unnecessary.
RSA-only, EC-only, and combined keyboxes are supported. When only one algorithm
is present, its key signs attestation leaves for both RSA and EC subject keys.
RSA private keys accept unencrypted PKCS#1 or PKCS#8 PEM encoding and normalize
to PKCS#1 for identity hashing and XML export.
EC private keys accept unencrypted SEC1 or PKCS#8 PEM encoding and normalize
to SEC1 for identity hashing and XML export. Adding or removing only the
PKCS#8 wrapper preserves the keybox identity when the inner SEC1 fields and
certificate chain are unchanged. A named curve carried only in the PKCS#8
algorithm identifier is restored into the SEC1 parameters.
The reload preserves ordinary application signing keys, including passkey
credentials. Only dedicated `ATTEST_KEY` entries tied to the previous keybox
are retired.

## `config.toml`

### Complete annotated example

The values under `[crypto]` below are deliberately non-working redaction
placeholders. A real active file contains unique generated hexadecimal values.
Never paste the placeholder values into a device and never replace the values
already present in a working file. The `[trust]` and `[device]` values are also
examples; keep the values from the active file unless you intend to change the
reported identity.

```toml
# Configuration format. Keep this at 2.
version = 2

[main]
# The supported service connection. Keep this value unchanged.
backend = "injector"
# KeyMint log detail: off, error, warn, info, debug, or trace.
log_level = "debug"
# Insecure biometric compatibility switch. Keep false for normal use.
force_skip_system_biometric_hat_verification = false
# Extra random wait per software TA call: inclusive [minimum, maximum] in ms.
# These defaults also apply when fields are absent; [0, 0] disables a category.
ta_operation_delay_ms = [9, 21]
ta_generation_delay_ms = [6, 16]
ta_control_delay_ms = [1, 4]

[crypto]
# Redacted placeholders only. Keep the generated 64-character values.
root_kek_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
kak_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_nonce = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# Optional expert override. Normally leave this line absent.
# auth_token_hmac_key = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"

[trust]
# Detect the Android major at each keymint start; use an integer to fix it.
os_version = "auto"
# Use auto, latest, or an exact YYYY-MM-DD date; boot also accepts decimal u32.
security_patch = "auto"
os_patchlevel = "auto"
vendor_patchlevel = "auto"
boot_patchlevel = "auto"
# Use auto, random, or exactly 64 hexadecimal characters.
vb_key = "auto"
vb_hash = "auto"
# Report verified boot and a locked bootloader when true.
verified_boot_state = true
device_locked = true

[device]
# Device identity strings reported when an app requests attestation IDs.
brand = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
device = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
product = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
manufacturer = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
model = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
serial = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# false fills only empty telephony fields from the device when available.
overrideTelephonyProperties = false
# Empty optional identifiers are valid; do not invent missing values.
meid = ""
imei = ""
imei2 = ""
```

### Top-level field

#### `version`

This identifies the configuration format. The supported value is the integer
`2`. It is not an Android version or an OMK release number. Do not increment it;
the current file should keep this value unchanged. Live reload rejects other
values and keeps the last valid runtime configuration.

At keymint startup, a missing `version` is treated as `0`. Versions `0` and `1`
are migrated in place to `2` before the service starts, and `os_version` is set
to `"auto"` so later Android upgrades are detected on the next keymint start.
Startup also removes the obsolete `trust_record`. For version `0`, missing
patch-level fields inherit the configured `security_patch`. Other configured
and unknown values are preserved. Migration is not performed during live
reload, so restart keymint to migrate an older file. An unsupported future
version is never overwritten.

### `[main]`

#### `backend`

Use `"injector"`. It is the only supported user choice and there is no
alternative runtime backend to select, so this field should be left unchanged.

#### `log_level`

This controls messages written by keymint. Use one of `"off"`, `"error"`,
`"warn"`, `"info"`, `"debug"`, or `"trace"`. `"debug"` is the default and is
the most useful level for a bug report. `"trace"` is more verbose; `"off"`
suppresses normal logging.

Changing this field requires a keymint restart. An unrecognized value falls
back to `debug`, but relying on that fallback can hide a spelling mistake.

Keymint and injector apply the same per-process burst limits before writing
to logcat, the console, and their rotating files. Each source location can
write four warning records per 30 seconds and 32 debug or trace records per
second. A structured `event=log_rate_limit` record reports the number suppressed
when that source is used again after the window, or when logs are flushed.
Error and info records are not rate limited. The in-memory limiter keeps only
bounded source metadata and counters; it does not retain message payloads.
AAID diagnostics contain the caller UID and package/signature counts, without
package names, signing-certificate bytes, challenges, tokens, or key material.

#### `force_skip_system_biometric_hat_verification`

This is an insecure compatibility switch for a device whose System KeyMint
cannot verify biometric authentication tokens correctly. When `true`, OMK
accepts a token whose structure is valid without asking System KeyMint to
verify its authentication code.

Keep it `false` unless a maintainer is diagnosing a confirmed device-specific
problem. It does not hide root and is not a general fix for fingerprint or
lock-screen failures. A valid save applies to new checks without restarting
keymint.

#### TA delay ranges

These three `[main]` fields configure extra random waits before OMK dispatches
calls to its software TA:

| Field | Default range (ms) | Covered TA calls |
| --- | --- | --- |
| `ta_operation_delay_ms` | `[9, 21]` | `begin`, `updateAad`, `update`, `finish`, `abort`, `getKeyCharacteristics` |
| `ta_generation_delay_ms` | `[6, 16]` | `generateKey`, `importKey`, `importWrappedKey`, `upgradeKey`, `convertStorageKeyToEphemeral` |
| `ta_control_delay_ms` | `[1, 4]` | `getHardwareInfo`, `addRngEntropy`, `deleteKey`, `deleteAllKeys`, `destroyAttestationIds`, `earlyBootEnded`, `getRootOfTrustChallenge`, `getRootOfTrust`, `sendRootOfTrust`, `setAdditionalAttestationInfo` |

Each value must be an array of exactly two integers, `[minimum, maximum]`,
with `0 <= minimum <= maximum <= 250`. Both endpoints are milliseconds and
are inclusive. `[0, 0]` disables that category; equal nonzero endpoints request
a fixed wait. Omitting a field enables its default range from the table.

For every covered TA invocation, OMK samples a new wait uniformly at
microsecond granularity between the configured endpoints. Calls in a category
share the same range, but do not reuse one sample for the category or thread.
The wait is added to processing time; it is neither a target total duration
nor a cap. Scheduling can extend the wait beyond the selected value, and one
app request that makes several covered TA calls accumulates their waits.

The wait occurs before TA dispatch and before acquiring the TA mutex, with the
configuration read guard released. The caller's Binder worker, RPC connection,
per-operation concurrency guard, or database guard can remain occupied during
the wait. Concurrent requests can therefore delay one another. A dispatched
call receives its wait even if the TA returns an error; validation failures
that return before TA dispatch do not. Raw TA initialization, local cache and
authentication helpers, and calls routed to System are excluded.

Valid changes apply to new TA calls without restarting keymint. A malformed
array, non-integer value, out-of-range endpoint, or reversed range rejects the
configuration; live reload keeps the previous valid configuration. Edit these
fields in the existing active file while preserving its other values. OMK
generates `config.toml` on the device; the module does not ship a reusable main
configuration template.

These waits are independent of the fixed
[`attestation_generation_delay_ms`](#attestation_generation_delay_ms) and
[`operation_start_delay_ms`](#operation_start_delay_ms) settings in
`injector.toml`. An applicable nonzero injector delay is added as well. For
example, `operation_start_delay_ms = 12` plus the default TA operation range
adds a 12 ms wait before the RPC and a separately sampled 9-21 ms wait before
the TA `begin` call. Set both injector delays to `0` if only the TA ranges are
wanted. Changing software timing does not provide hardware security, constrain
total calls to a hardware timing interval, or guarantee a detector result.

### `[crypto]`

Every value in this section is private. Each value is exactly 32 bytes written
as 64 hexadecimal characters using `0-9` and `a-f`. OMK generates these values
when it creates a new configuration.

Keep all four generated seed and nonce fields present and stable, and back them
up privately with the OMK data. Changing or removing any of them requires a
keymint restart and can make existing keys or authentication-bound operations
unusable. Values from another device and the redacted placeholders in this
guide are not replacements for the active values.

If `shared_secret_seed` or `shared_secret_nonce` is missing, OMK generates a
new random replacement when it reads the file. That is not a stable active
configuration, so make sure both generated values remain present.

#### `root_kek_seed`

This seed is used to derive key material that protects OMK key blobs. If it
changes, OMK may no longer be able to open keys created with the previous
value. It must be present and must remain unchanged.

#### `kak_seed`

This seed is used for OMK's key-agreement protection. It belongs to the same
device-specific secret set as `root_kek_seed`. It must be present and must
remain unchanged.

#### `shared_secret_seed`

This is the seed half of the shared-secret parameters used for authentication
token verification. Preserve it together with `shared_secret_nonce`; changing
only one side still changes the resulting secret.

#### `shared_secret_nonce`

This is the nonce half of the shared-secret parameters. It is also a full
64-character hexadecimal value, not a short counter or a value to regenerate
manually.

#### `auth_token_hmac_key`

This optional field supplies an explicit authentication-token HMAC key.
When it is absent, OMK derives the required key through
`shared_secret_seed` and `shared_secret_nonce`. Ordinary users should leave the
field absent. If it is explicitly present, it must also contain exactly 64
hexadecimal characters and must be kept private and stable.

### `[trust]`

These fields control values reported through key attestation. They do not
repair hardware, renew a certificate, remove a keybox revocation, or hide root.

#### `os_version`

Use `"auto"` to detect the current Android major each time the keymint process
starts, or use an integer from `0` through `99` to keep a fixed major such as
`12`, `16`, or `17`. Do not write a dotted release, SDK number, or security
patch date here. KeyMint encodes the resolved major with the AOSP `MMmmss`
formula, so fixed `16` is reported as `160000`. Changing this field requires a
keymint restart.

#### `security_patch`

This controls `ro.build.version.security_patch`. It accepts:

- `"auto"`: use the current `ro.build.version.security_patch` value without
  writing it;
- `"latest"`: use the fifth day of the current calendar month when the value
  is resolved; or
- an actual date written as `"YYYY-MM-DD"`, including leading zeroes.

The WebUI **Sync security patch** action is separate from the `"latest"` mode.
It reads the main table on Google's Android Security Bulletin overview,
selects the greatest published security-patch date that is not in the future,
and uses its year and month as the newest published patch month. The day is
selected from the saved default `ro.build.version.security_patch`: day `01`
uses day `01` in that newest month, while day `05` uses the Google bulletin
date unchanged. Any other saved day also keeps the Google bulletin date. If
the saved `ro.build.version.security_patch` and
`ro.vendor.build.security_patch` dates differ, the system value determines
the day behavior. For example, when the newest Google date is `2026-08-05`, a
saved system default of `2025-06-01` synchronizes `2026-08-01`, while
`2025-06-05` synchronizes `2026-08-05`. This does not change the separate
`"latest"` mode described above. The action never guesses an unpublished
current-month patch month. It requires network access to Google's official
bulletin host or mirror; if access or parsing fails, no file or property is
changed. The native helper validates the selected date again and preserves all
unrelated configuration values. After a successful sync or restore, the WebUI
shows a completion message asking you to reboot the device; it does not reboot
automatically.

Before changing runtime properties for the first sync, the helper atomically
saves both default properties to
`/data/misc/keystore/omk/data/security_patch_defaults.toml`. When all four
`[trust]` patch-level fields are `auto`, those defaults are read from the
current runtime properties; for an explicit date or a mixed configuration, they
are read from the trusted `build.prop` sources. An existing valid snapshot for
the same build fingerprint is retained across repeated syncs. The helper then
sets both properties to the selected date with `resetprop -n` and verifies the
results. After that, it writes the date to `security_patch`, `os_patchlevel`,
`vendor_patchlevel`, and `boot_patchlevel`. These are global Android properties
for the current boot, not values visible only to OMK.

While a valid defaults snapshot exists and all four configuration fields still
contain the same exact date, the module's early boot hook reapplies that date to
both properties before Android framework values are cached. Keymint also
reapplies the pair at startup. The snapshot is the persistent marker for a
WebUI synchronization: a manually authored exact-date configuration without a
snapshot follows the normal patch-level path and does not cause an extra
vendor-property write. If the optional snapshot cannot be read or validated,
both paths skip this paired reapply and keymint continues its normal
initialization.

The WebUI **Restore default security patch** action uses the saved snapshot and
does not access the network. If the snapshot is absent, the helper records the
current runtime properties as the restore values. It restores both properties
first, writes `"auto"` to `security_patch`, `os_patchlevel`,
`vendor_patchlevel`, and `boot_patchlevel`, and deletes the snapshot only when
every step succeeds. It preserves every other configuration value. A malformed
or unverifiable snapshot stops the operation before either property or the
configuration changes. A failed paired property update is rolled back. If the
configuration write fails, the helper attempts to roll back both properties;
any incomplete restore retains the snapshot so the action can be retried. The
helper serializes these actions with startup and live configuration reloads so
an older pending reload cannot overwrite a completed restore.

`"auto"` first uses a nonempty runtime property, then the exact key from the
standard `build.prop` locations, and finally `2025-06-05` if neither source is
available. A present runtime value is used as-is rather than replaced by a
`build.prop` value. `"latest"` and an exact date intentionally overwrite an
existing runtime property, but OMK never creates or deletes it. `"auto"` never
writes the property. After an explicit or `"latest"` override, manually
switching back to `"auto"` in the same boot keeps the current runtime value;
reboot to restore the system-provided value. The WebUI restore action instead
restores the saved system and vendor runtime properties before writing `"auto"`.

#### `os_patchlevel`

This controls the KeyMint OS patch level. `"auto"` follows the effective
`security_patch`; `"latest"` and an exact `"YYYY-MM-DD"` date override it for
KeyMint without writing another property. The final value is parsed with the
AOSP `YYYY-MM-DD` parser and encoded as `YYYYMM`.

#### `vendor_patchlevel`

This controls the KeyMint vendor patch level. `"auto"` first reads the nonempty
runtime `ro.vendor.build.security_patch`, then the exact key from the standard
`build.prop` locations, and finally falls back to the effective
`os_patchlevel`. `"latest"` and an exact `"YYYY-MM-DD"` date are also accepted.
The final value is parsed with the AOSP `YYYY-MM-DD` parser and encoded as
`YYYYMMDD`. A present nonempty source is not replaced by a lower-priority source
merely because parsing later fails. Normal patch-level resolution does not write
the vendor property; the WebUI sync and restore actions explicitly update it as
described above.

#### `boot_patchlevel`

This controls the KeyMint boot patch level. `"auto"` first reads
`com.android.build.boot.security_patch` from the active top-level vbmeta image.
If the property is absent, OMK reads the same property from the active boot
image's standalone or AVB-footer embedded vbmeta, then falls back to the boot
header. The legacy header field stores a year and month but no day, so its wire
value ends in `00`; an all-zero field therefore becomes `20000000`, but only
after neither vbmeta location supplied the property. If boot-metadata resolution
fails, OMK uses this fallback order: nonempty runtime
`ro.vendor.boot_security_patch`, the exact key from the standard `build.prop`
locations, then the effective `os_patchlevel`.

`"latest"`, an exact `"YYYY-MM-DD"` date, and a decimal `u32` wire value are
also accepted. The decimal form preserves bootloader wire values such as
`"20000000"` without interpreting them as dates. These explicit modes do not
read boot metadata. Boot patch-level resolution does not read the system TEE or
write the boot property. During hot reload, an unchanged `"auto"` keeps the
value resolved before keymint dropped privileges; switching from an override
back to `"auto"` takes effect after keymint restarts. Explicit dates are encoded
as `YYYYMMDD`.
If the selected value cannot be converted, startup fails; a failed hot update
keeps the previous runtime configuration.

The four patch-level fields are resolved and applied together while keymint is
running when no other `[trust]` field changes in the same save. Existing TAs are
updated in place so in-flight operations and per-boot counters remain intact;
equivalent boot representations do not trigger an update. If the matching log
reports that the live update failed, restart keymint.

#### `vb_key`

This controls the 32-byte verified-boot public-key digest:

- `"auto"` reuses the public digest saved in
  `/data/misc/keystore/omk/data/vbmeta_state.toml`. When no snapshot exists, it
  first reads `ro.boot.vbmeta.public_key_digest`, then tries to calculate the
  top-level vbmeta key digest, and uses a random fallback only if neither source
  is available. That first result is atomically saved before KeyMint serves keys;
- `"random"` generates a new value whenever keymint starts; or
- a 64-character hexadecimal string pins an exact value.

The snapshot contains a format version and the public 32-byte digest as 64 hex
characters, not a private key. It is shared by TEE and StrongBox and is retained
across keymint restarts, reboots, slot changes, and OTA updates. Reusing it does
not overwrite the Android boot property. An unreadable or invalid snapshot, or
a failure to save the first value, stops startup instead of selecting a new key.
Back it up together with `config.toml` and the rest of OMK's data; do not delete
it to troubleshoot an existing KeyBlob.

Explicit hex and `"random"` modes do not create, read, or replace the auto
snapshot. Returning to `"auto"` reuses that snapshot if present. If none exists
and `"random"` was active, reboot the whole device before using `"auto"` so the
original boot property is restored before its first snapshot is captured.

Changing this field requires a keymint restart. The verified-boot key, locked
state, and verified-boot state are bound into KeyBlob encryption; deliberately
changing any of them can make existing keys unreadable. `"random"` changes the
key on every startup and is unsuitable for retaining such keys. Pinning a
current value does not recover blobs created with a different, unknown value.

#### `vb_hash`

This controls the 32-byte verified-boot hash:

- `"auto"` first reads `ro.boot.vbmeta.digest`, then tries the original System
  attestation hash, and uses a random fallback only if neither source is
  available;
- `"random"` generates a new value whenever keymint starts; or
- a 64-character hexadecimal string pins an exact value.

Restart keymint after a normal change, and reboot the whole device when
returning from `"random"` to `"auto"`. This field is not stored in the public-key
snapshot: auto mode resolves the current hash on each startup. It is included
in attestation but not in the Root of Trust input used for KeyBlob encryption.

#### `verified_boot_state`

`true` reports the verified boot state as verified; `false` reports it as
unverified. This is independent of the `device_locked` switch. Changing it
requires a keymint restart.

#### `device_locked`

`true` reports that the device boot state is locked; `false` reports it as
unlocked. This does not actually lock or unlock the bootloader. Changing it
requires a keymint restart.

### `[device]`

This section supplies device identity strings when an app explicitly requests
attestation IDs. These values are personal data. Use the values already
generated for the device, and restart keymint after changing this section so
the one-shot attestation-ID snapshot is rebuilt.

#### `brand`

The product brand reported in an attestation ID request, normally based on
`ro.product.brand` when a new configuration is created.

#### `device`

The device code name reported in an attestation ID request, normally based on
`ro.product.device`.

#### `product`

The product name reported in an attestation ID request, normally based on
`ro.product.name`.

#### `manufacturer`

The manufacturer name reported in an attestation ID request, normally based on
`ro.product.manufacturer`.

#### `model`

The model name reported in an attestation ID request, normally based on
`ro.product.model`.

#### `serial`

The device serial reported in an attestation ID request, normally based on
`ro.serialno`. Treat it as private information and redact it from reports.

#### `overrideTelephonyProperties`

With the recommended value `false`, OMK tries to fill only empty `imei`,
`imei2`, and `meid` fields from the device's telephony services and property
fallbacks. A configured non-empty value is preserved, and OMK attempts to write
each successfully discovered value back to the active `config.toml`.

With `true`, OMK skips telephony discovery and uses the three configured fields
exactly as written, including empty strings. Use this only when intentionally
pinning the values.

#### `imei`

The primary IMEI. Leave it empty when the device has no IMEI or when automatic
discovery should fill it. Do not invent a value to satisfy an app.

#### `imei2`

The second IMEI. Single-SIM and some dual-SIM devices can legitimately leave it
empty. Its absence does not invalidate `imei` or the non-telephony device
fields.

#### `meid`

The MEID used by devices that provide one. Many devices have no MEID, so an
empty value is valid. Its absence does not invalidate an available IMEI.

### `config.toml` apply summary

| Fields | Required action |
| --- | --- |
| `[main].log_level` | Restart keymint. |
| `[main].force_skip_system_biometric_hat_verification` | Applies to new checks after a valid save. |
| `[main].ta_operation_delay_ms`, `ta_generation_delay_ms`, `ta_control_delay_ms` | Apply to new TA calls after a valid save; invalid ranges retain the previous configuration. |
| All `[crypto]` fields | Restart keymint; changing values can make keys unusable. |
| `[trust].security_patch`, `os_patchlevel`, `vendor_patchlevel`, `boot_patchlevel` | Hot-apply as a group when no other `[trust]` field changes; otherwise restart keymint. |
| `[trust].os_version` | Restart keymint. |
| Other `[trust]` fields | Restart keymint. |
| All `[device]` fields | Restart keymint to rebuild the cached ID snapshot. |
| `vb_key` from `"random"` to `"auto"` | Restart keymint to reuse its saved auto snapshot; reboot the device if none exists. |
| `vb_hash` from `"random"` to `"auto"` | Reboot the whole device. |

## `injector.toml`

### Complete annotated example

```toml
# Configuration format. Keep this at 1.
version = 1

# Add one exact package name per line. Blank lines and lines whose first non-space character is # are ignored.
# Bare entries omit quotes and commas; keep the surrounding scoop = [ ... ] lines.
scoop = [
  io.github.vvb2060.keyattestation
  com.google.android.gsf
  com.google.android.gms
  com.android.vending
  com.eltavine.duckdetector
]

[main]
# Master switch for request routing. Keep true for normal use.
enabled = true
# Injector log detail: off, error, warn, info, debug, or trace.
log_level = "debug"
# Optional delay before challenged OMK generation, 0..250 ms.
attestation_generation_delay_ms = 0
# Optional delay before two-way OMK createOperation calls, 0..250 ms.
operation_start_delay_ms = 0

[filter]
# Enforce scoop and the safety rules below.
enabled = true
# Packages that must never use OMK, even if another shared package is in scoop.
deny_packages = []
# Block core Android and system identities. Keep true.
block_android_package = true
# Reject callers whose package name cannot be found. Keep false.
allow_unknown_package = false

[intercept]
# Route each named KeyStore operation to OMK for an allowed caller.
get_security_level = true
get_key_entry = true
update_subcomponent = true
list_entries = true
delete_key = true
grant = true
ungrant = true
get_number_of_entries = true
list_entries_batched = true
get_supplementary_attestation_info = true
```

### Top-level fields

#### `version`

This identifies the injector configuration format. Keep the integer value `1`.
It is not an Android version or an OMK release number. Live reload rejects
other values and keeps the last valid runtime configuration.

At injector startup, a missing `version` is treated as `0`, and version `0` is
migrated in place to `1` while preserving the rest of the file. Version `0` is
not migrated during live reload, so restart the injector to migrate such a
file. An unsupported future version is never overwritten.

If a documented injector field is omitted, its default value is used. Unknown
fields in the documented top-level and named sections are rejected, so do not
add names that are not described in this guide.

#### `scoop`

This array selects current Android callers that may use OMK. Supported targets
are an exact package name for every Android user, `package@user_id` for one
Android user, and `uid:full_android_uid` for one complete caller UID. For
example, `com.example.app@10` selects that package in user 10, while
`uid:1010123` selects UID 1010123, not UID 10123 in user 0. User IDs are decimal
integers in `0..=42949`; full UIDs are in `0..=4294967295`. UID targets still
require normal package resolution unless `allow_unknown_package` permits an
unresolved caller; they do not override safety or deny settings.

Keep the surrounding `scoop = [` and `]` lines and add one target per line,
matching the line-oriented package list used by TrickyStore. Bare entries omit
both quotes and commas. Empty lines and lines whose first non-space character
is `#` are ignored, and surrounding spaces are trimmed. The traditional
quoted, comma-separated TOML array form is also accepted. Empty entries are
removed and decimal identifiers are canonicalized before duplicate entries are
reduced to one when the file is loaded. A bare package and a user-specific
target may coexist. App
labels, partial names, and wildcards are not accepted. TrickyStore's `!`
generate suffix is not interpreted. Invalid selectors reject the configuration;
a failed reload keeps the previous valid settings active.

The embedded WebUI presents an icon, application name, package name, and
selection control for each installed package. Multiple Android users have
separate groups and user-specific selections. A WebUI save merges only the
user's additions and removals into the current normalized `scoop` list;
`[main]`, `[filter]`, `[intercept]`, and per-package tables retain their current
values. Opening the package selector, returning to it from another app,
pulling down at the top, or using its refresh action reloads installed packages
and saved selections without discarding unsaved edits. Pull-to-refresh uses an
elastic capsule indicator and a release threshold. Existing rows and loaded
icons remain visible while refreshing; a full loading view is used only before
the first package snapshot is available.
The gesture is coalesced to animation frames and moves the list with compositor
transforms, without resizing the list layout on each touch event. Refresh state
is painted before configuration and package-manager bridge queries begin.

**Automatically add new apps** is disabled by default and saves immediately.
Enabling it records a baseline of installed user applications without selecting
them. While enabled, OMK checks for new user applications in the background,
including when the WebUI is closed, and adds user-specific `package@user_id`
targets. System applications are excluded. App updates and unchanged installed
apps do not re-add a manually deselected target. Disabling the option leaves
existing selections unchanged; enabling it again records a fresh baseline.
The switch and per-user package snapshots are stored in
`/data/misc/keystore/omk/data/auto_targets.json`. An unreadable user profile keeps
its previous snapshot; a newly discovered profile is baselined on its first
successful scan. The background worker checks at approximately one-minute
intervals and on relevant package-list changes, so detection is not immediate.

Android can assign several packages the same identity. In that case, listing
any one of those packages allows the shared identity, unless a filter rule
rejects one of the packages in the group. Adding or removing a package does not
move or convert keys between System and OMK; an app may lose access to keys it
created through the other route.

There is one narrow granted-key exception. An app outside `scoop`, or one whose
package name cannot be resolved, can still use a key-access grant that OMK
confirms belongs to an OMK key. This keeps a key deliberately shared by another
app usable without giving the receiving app general OMK access. Android-blocked
and deny-listed callers do not receive this exception.

### `[main]`

#### `enabled`

This is the injector's master routing switch. `true` lets the filter and
`[intercept]` settings decide each new request. `false` stops new OMK routing so
normal requests continue to System. Keep it `true` for normal OMK use.

Avoid changing this switch while an app has a key operation open. Save the
change, restart the injector, and reopen the app when deliberately switching
routes.

#### `log_level`

This controls injector messages. Accepted values are `"off"`, `"error"`,
`"warn"`, `"warning"`, `"info"`, `"debug"`, and `"trace"`; `"warning"` is an
alias for `"warn"`. Matching is case-insensitive, but lowercase values are
recommended. `"debug"` is the default and the normal choice for a bug report.

A valid file change updates the level without restarting the injector. An
unrecognized string does not make the TOML file invalid; the injector uses
`debug` instead.

The shared logging burst policy above also applies to injector logcat and
file output. Changing the log level does not reset the current burst counters.

#### `attestation_generation_delay_ms`

Optional timing workaround, an integer from `0` to `250` milliseconds. The
default `0` disables it. A nonzero value delays OMK `generateKey` requests
containing `ATTESTATION_CHALLENGE` before the generation RPC starts. Both
two-way and one-way requests receive this delay, including calls that return
OMK business errors. Plain generation, imports, operations, System requests,
and failures before generation dispatch do not receive this delay.

This can mitigate clients that classify software KeyMint by generation
timing. It does not provide hardware security or guarantee a detector result.
For example, `25` adds at least 25 ms before each affected generation;
scheduling can add more. The wait occurs before creating or storing the new
key, without holding the RPC connection or KeyMint/database locks. The Binder
worker stays occupied, so concurrent requests can delay unrelated callers.
Key storage and reply delivery remain separate steps; this setting does not
promise that a concurrent reader cannot observe a key before the generation
reply arrives. Leave it at `0` unless needed.
This fixed wait adds to any applicable [`config.toml` TA waits](#ta-delay-ranges).

Valid changes apply without a restart. Out-of-range or non-integer values
reject the configuration; on reload, the previous valid settings remain active.

#### `operation_start_delay_ms`

Optional timing workaround, an integer from `0` to `250` milliseconds. The
default `0` disables it. A nonzero value delays two-way OMK `createOperation`
requests before the operation RPC starts. Both successful calls and calls that
return OMK business errors receive this delay. One-way calls, System requests,
and other methods do not receive this delay.

For example, `12` adds at least 12 ms to each affected operation start;
scheduling can add more. The waiting Binder worker stays occupied, so many
concurrent calls can delay unrelated callers. Waiting occurs before creating
the operation, without holding the RPC connection or KeyMint/database locks,
and does not allocate an operation slot during the wait. Existing operations
remain subject to their normal lifecycle and pruning rules.

This option can mitigate clients that classify software KeyMint by operation
timing. It does not alter permission checks, key metadata, routing, or reported
security levels, provide hardware security, or guarantee a detector result.
Leave it at `0` unless needed. Valid changes apply without a restart.
Out-of-range or non-integer values reject the configuration; on reload, the
previous valid settings remain active.
This fixed wait adds to any applicable [`config.toml` TA waits](#ta-delay-ranges).

### `[filter]`

With the filter enabled, OMK evaluates a caller in this order:

1. Reject a core Android or system identity when
   `block_android_package = true`.
2. If its package names cannot be resolved, follow `allow_unknown_package`.
3. Reject the whole identity if any resolved package is in `deny_packages`.
4. Reject it if no `scoop` target matches its current UID, package, and Android user.
5. Otherwise allow it to use the enabled `[intercept]` routes.

This order matters for packages that share an Android identity: a deny rule
wins over a matching entry in `scoop`.

After this normal filter decision, the narrow OMK-owned grant exception
described under `scoop` can preserve access for an unknown or out-of-scope app.
It does not override the Android-package block or `deny_packages`.

#### `enabled`

`true` enforces `scoop`, the deny list, the Android-package block, and the
unknown-package policy. `false` bypasses all four checks and allows every
caller to reach any operation enabled under `[intercept]`.

Disabling the filter can route Android services and unrelated apps to OMK and
can break unlocking, app storage, or the user interface. Keep it `true`.

#### `deny_packages`

This is an array of exact package names that must not use OMK. It is useful
when a selected package shares its Android identity with another package that
must stay on System. If any package resolved for the identity is denied, the
entire identity is rejected even when another package is listed in `scoop`.

An empty array, `[]`, is the default. This list uses the standard quoted,
comma-separated TOML array format; the line-based shorthand is specific to
`scoop`.

#### `block_android_package`

`true` rejects core Android and system identities before `scoop` is considered.
It also rejects resolved package names equal to `android` or beginning with
`android.`. It does not mean that every ordinary app whose name begins with
`com.android.` is automatically blocked.

Keep this setting `true`. Setting it to `false` only removes this safety check;
the remaining filter rules still apply.

#### `allow_unknown_package`

This controls a caller whose Android package name cannot be resolved. `false`
rejects that caller, which is the safe default. `true` allows an unresolved app
identity without requiring a match in `scoop`; core Android identities are
still rejected when `block_android_package = true`.

This setting is not an "all apps" switch. Keep it `false` unless a maintainer
has confirmed that a supported app cannot be resolved normally.

### `[intercept]`

Each switch controls one Android KeyStore service operation. For a caller
allowed by the filter, `true` routes that operation to OMK and `false` leaves
that operation on System. These switches do not migrate existing keys or make
System-created key references usable by OMK.

Service, maintenance, and authorization requests must match the actual Binder
object registered for their interface before OMK dispatch or state mirroring.
An interface token naming a different Binder service is left to the system
interface check and does not trigger OMK work. Registered Binder identities
are resolved independently on a dedicated thread. If an identity is not yet
available, calls requiring OMK execution or mandatory state mirroring return
`SYSTEM_ERROR` without executing a backend; calls configured for System stay
on System. Best-effort authentication-token updates also stay on System while
their service identity is unavailable. Missing service identities are retried
automatically.

Isolated Android service callers use the system ActivityManager process record
for package attribution when ordinary UID package lookup has no result. The
privileged helper matches the Binder caller PID and checks its kernel UID and
process start time before and after the lookup. Only the process package list
affects the existing package filter; dependency packages are excluded. Null
package-list entries are ignored; present package names must pass validation. The
original isolated UID, PID, and SELinux identity remain authoritative for key
permissions. Failed or unsupported lookups retain unknown-package behavior.
The ActivityManager transaction number is read from the installed system
framework's AIDL Stub constant, allowing vendor method-number changes without
probing unknown transactions. The constant is cached only in memory; process
ownership is queried and checked for each unresolved isolated caller request.
This attribution has no key-descriptor or backend-origin dependency and does
not override deny lists or per-method interception settings.

The OMK-owned grant exception is separate from ordinary package routing. A
request carrying a confirmed OMK grant may return to OMK even when the
receiving app is outside `scoop`, so the granted key remains usable.

Keep all switches `true` for normal use. Mixing System and OMK operations for
the same app can cause missing-key errors, inconsistent lists, or failed
follow-up operations.

Calls on an OMK operation handle follow the Keystore2 concurrency contract.
Overlapping `updateAad`, `update`, `finish`, or `abort` calls on the same handle
return `OPERATION_BUSY` (19) while another call is in progress. A busy response
leaves that operation usable. Each operation has its own concurrency guard,
so calls on different handles do not contend on this guard.

The software TA allocates 32 concurrent operation slots for an AIDL KeyMint
TEE profile and 16 for a legacy Keymaster TEE profile. StrongBox profiles
retain four slots. A full TA table returns `TOO_MANY_OPERATIONS` to the
existing Keystore2 pruning path; `finish` and `abort` release their slots.
These limits do not change request routing or provide hardware isolation.

#### `get_security_level`

Controls the request for a TEE or StrongBox KeyStore security-level handle.
Apps use this handle for later operations such as creating, importing, and
using keys.

#### `get_key_entry`

Controls retrieval of an existing key entry, including its metadata and the
handle used for later key operations.

#### `update_subcomponent`

Controls replacement of an existing key entry's certificate or certificate
chain components.

#### `list_entries`

Controls listing key aliases in a requested namespace.

#### `delete_key`

Controls deletion of a named key. The selected backend is authoritative; OMK
does not delete a matching System key as a substitute.

#### `grant`

Controls granting another app access to a key.

#### `ungrant`

Controls removal of a previously granted key permission.

#### `get_number_of_entries`

Controls counting the key entries in a namespace.

#### `list_entries_batched`

Controls paged or batched listing of key entries.

#### `get_supplementary_attestation_info`

Controls retrieval of supplementary information used by supported attestation
requests.

### Per-package subtables

Per-package tables such as `[scoop.com.example.app]` and values such as
`mode = "strict"` are not supported routing options. They may be preserved when
the file is parsed, but they do not change which backend handles a request. Do
not add them; use `scoop`, `[filter]`, and `[intercept]` instead.

### `injector.toml` apply summary

Every valid documented field change is loaded for new requests without a
device reboot. For `scoop`, `[main].enabled`, `[filter]`, or `[intercept]`
changes, restart the injector and reopen the affected app when you need a clean
boundary after a route change. A syntax error, an unknown field, or an
unsupported future `version` leaves the last valid runtime configuration
active; if present at injector startup, it leaves OMK request routing disabled
until the file is corrected.

The embedded WebUI can change `scoop`, install a locally selected keybox,
synchronize the four `[trust]` patch-level fields from the official Android
Security Bulletin, restore those fields to `"auto"`, manage the validated PIF
profile, and configure the Qualcomm Soter HAL relay used by the WeChat payment
fingerprint path. Security-patch sync and restore also manage
the two global runtime properties and the defaults snapshot described above.
Persistent native save paths validate the complete candidate before writing and
use atomic replacement. Successful saves enter the applicable watcher hot-reload
path.
