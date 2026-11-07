# Configuration Guide

OhMyKeymint (OMK) uses two core configuration files:

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
   the `scoop = [` and `]` lines, then add one quoted package name and comma per line;
   package selections apply to all Android users of that package.
4. Change one thing at a time, save the complete file, and check the matching
   log after the change.

Never publish `[crypto]` values, IMEI, IMEI2, MEID, serial numbers, or an
unredacted copy of either active file.

## How changes are loaded

Both components watch their active file for valid changes. Their behavior is
not identical:

- A valid `injector.toml` is applied to new requests without a reboot.
- A valid `config.toml` is read automatically. The four patch-level fields,
  biometric compatibility switch, keybox-retirement switch, and three TA delay
  ranges can take full effect without restarting keymint. The field reference
  below states when a restart is required.
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

## EC signing compatibility

P-256 signing keys may include redundant `Encrypt` and `Decrypt` purposes
alongside `Sign` (and optionally `Verify`). Those purposes do not select the
key type or enable EC encryption/decryption operations. Generation and import
apply the same checks regardless of parameter order. This exception does not
apply to encryption-only requests, other curves, key-agreement combinations,
or attestation keys. Curve25519 selects signing/attestation versus agreement
from its private-key purpose, independently of an accompanying `Verify` tag.

SID, operation challenge, authentication-token MAC and authentication timeouts
remain enforced when the key's authorization policy requires them.

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
PIF fingerprint through OMK's own Zygisk payload, and issuing a local RKP
Keybox. Open it from the Oh My Keymint module page in
KernelSU. With Magisk, open an installed KSUWebUIStandalone or WebUI X host and
select Oh My Keymint; the module does not install either host.

The WebUI has Home, Tools, and Settings pages. Each page opens with a MIUIX
large title that fades into the top app bar's small title over the first 48 px
of scrolling. Home starts with a status card showing whether OMK KeyMint is
running, its PID, or a loading or error state. Tools groups its entries into
**App management** (package selection), **Keybox & attestation** (**Change
Keybox**, **Remote key provisioning**, and **Local SOTER identities**), and
**Play Integrity** (**Spoof PIF fingerprint**, **Clear GMS cache**, and
**Security patch settings**). **Remote key provisioning** opens a bottom sheet
with **Fix RKP** and **Issue local RKP Keybox**. **Security patch settings**
shows the current patch date and opens a bottom sheet with **Sync security
patch** and **Restore default security patch**. Choosing a sheet action closes
the sheet before the action's own confirmation or panel opens. The close button,
a downward drag, or Android Back dismisses a sheet without leaving Tools. A row
shows a progress indicator while its action runs, and a sheet row is disabled
only when all of its actions are busy.

The main package picker shows user applications in separate **Selected package
names** and **Unselected package names** sections. System applications,
including Android overlays, are managed through **More > Add system apps**.
Checking or unchecking an app saves automatically in both the main picker and
the system-app sheet. Recommended selection and Deselect all also save
automatically. Writes are serialized and consecutive changes are coalesced;
clicks made during a bridge write retain their latest state for the next write.
The page shows saving progress and an explicit unsaved error with Retry on
failure. Failed edits remain visible for retry. Closing either picker does not
cancel a pending save; reopening retains unsaved edits and the error state.
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
Application rows keep icon-loading state locally so an icon decode does not
rerender the installed-app list. Bottom-sheet handle drags update a compositor
transform at most once per display frame, without rerendering their content or
changing layout height. Cancelled drags rebound without dismissing the sheet;
busy panels remain protected against dismissal. Mutating actions paint their
disabled/loading feedback before invoking the native bridge.
Pages scroll inside the app container rather than the Android WebView viewport.
Scroll indicators are hidden throughout pages, lists, menus and dialogs; touch,
wheel and keyboard scrolling remain available. Per-page scroll restoration and
package pull-to-refresh use that same app container.

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
The package picker's top bar and menu follow the same bar-blur setting and use
opaque surfaces when blur is disabled or unsupported. Interface-scale dragging
previews the percentage locally; releasing applies and saves the page scale.
Cancelling the gesture discards the preview. Keyboard arrow/Home/End changes
are applied on key release or blur.
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
the registered TEE and StrongBox KeyMint services and the matching
`default` and `strongbox` RKP Binder services. A missing
optional StrongBox service is shown as unregistered. These checks do not issue
an attestation challenge, contact an RKP provisioning server, or certify
hardware-backed operation. A vendor KeyMint process is not used as evidence
that OMK itself is running. The current-device-status card shows service state
only, without Keybox certificate-chain details or a separate inspector request.
A diagnostic read failure is reported in the UI and does not change runtime
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
examples; keep the values from the active file unless the reported identity
needs to change.

```toml
# Configuration format. Keep this at 3.
version = 3

[main]
# The supported service connection. Keep this value unchanged.
backend = "injector"
# KeyMint log detail: off, error, warn, info, debug, or trace.
log_level = "debug"
# Insecure biometric compatibility switch. Set false to require System MAC verification.
force_skip_system_biometric_hat_verification = true
# Extra random wait per software TA call: inclusive [minimum, maximum] in ms.
# These defaults also apply when fields are absent; [0, 0] disables a category.
ta_operation_delay_ms = [9, 21]
ta_generation_delay_ms = [6, 16]
ta_control_delay_ms = [1, 4]
# Retire dedicated ATTEST_KEY entries bound to a previous keybox identity.
retire_stale_keybox_bound_keys = true

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
`3`. It is not an Android version or an OMK release number. Do not increment it;
the current file should keep this value unchanged. Live reload rejects other
values and keeps the last valid runtime configuration.

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
Error and ordinary info records are not rate limited. The in-memory limiter keeps only
bounded source metadata and counters; it does not retain message payloads.
AAID diagnostics contain the caller UID and package/signature counts, without
package names, signing-certificate bytes, challenges, tokens, or key material.

#### `force_skip_system_biometric_hat_verification`

This is an insecure compatibility switch for a device whose System KeyMint
cannot verify biometric authentication tokens correctly. When `true`, OMK
accepts a directly submitted, structurally valid fingerprint-only token without
asking System KeyMint to verify its authentication code. Password, combined
and unknown authenticator types do not receive this exception.

The default is `true`, including when the field is omitted from `[main]`.
An explicit `false` requires System KeyMint MAC verification for direct tokens.
This compatibility default weakens authentication-token verification; use `false` when System
KeyMint can verify the device's tokens. It does not hide root and is not a
general fix for fingerprint or lock-screen failures. A valid save applies to
new checks without restarting keymint.

Tokens mirrored after successful System `addAuthToken` ingestion follow the
separate existing mirror path regardless of this switch. A successful System
ingestion is not itself proof of a valid hardware MAC. The switch cannot fix
a failure in EC key creation, mirrored token delivery or key-specific SID,
challenge, timeout and local-MAC checks.

Logs distinguish `event=auth_token_received` sources (`direct` or
`system_mirror`), `event=auth_token_verification` modes (`system_mirror`,
`biometric_compatibility` or `system_mac`), and `event=auth_token_rejected`
stages (`shape`, `system_mac` or `localization`). A mirror localization failure
logs `event=auth_token_dropped stage=localization` and preserves System success.
`event=auth_token_cached stage=localized` confirms local token
ingestion, not a successful application signature or payment. Token ingestion
does not log raw MACs, full challenges or secure user/authenticator IDs.

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

#### `retire_stale_keybox_bound_keys`

When `true`, changing the active `keybox.xml` retires dedicated `ATTEST_KEY`
entries bound to the previous keybox identity. The default is `true`. Ordinary
application signing keys, including passkey credentials, are retained.

Set it to `false` only when dedicated attestation keys must remain stored across
keybox changes. This does not replace their existing certificate identity with
the new keybox identity.

The value is read when keybox-bound retirement runs, so a saved change applies
to the next keybox reload or keymint restart.

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

When the first automatic resolution must generate a random fallback, OMK also
pins that generated value in `config.toml` as an exact hexadecimal value. The
public snapshot remains available if the setting is later returned to `"auto"`.

#### `vb_hash`

This controls the 32-byte verified-boot hash:

- `"auto"` first reads `ro.boot.vbmeta.digest`, then tries the original System
  attestation hash, and if neither source is available, generates a value, saves
  it to `config.toml` as an exact hex value, and reuses that value on later
  keymint starts;
- `"random"` generates a new value whenever keymint starts; or
- a 64-character hexadecimal string pins an exact value.

Restart keymint after a normal change, and reboot the whole device when
returning from `"random"` to `"auto"`. This field is not stored in the public-key
snapshot: automatic source discovery runs at startup until a fallback is pinned
as an exact value in `config.toml`. It is included in attestation but not in the
Root of Trust input used for KeyBlob encryption.

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
# Standard TOML strings with a trailing comma; plain packages apply to all users.
scoop = [
  "io.github.vvb2060.keyattestation",
  "com.google.android.gsf",
  "com.google.android.gms",
  "com.android.vending",
  "com.eltavine.duckdetector",
  "com.oplus.engineermode",
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
# Exact shared-system-UID application process -> Binder SELinux context.
# Both this binding and a scoop entry are required.
system_app_contexts = { "com.oplus.engineermode" = "u:r:engineermode_app:s0" }

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

Keep the surrounding `scoop = [` and `]` lines and add one quoted target with
a trailing comma per line, using standard TOML array syntax. The template and
all configuration writers use this format. The reader also accepts line-based
entries without quotes or commas for compatibility. Empty lines and comment
lines are ignored, and surrounding spaces are trimmed. Empty entries are
removed and decimal identifiers are canonicalized before duplicate entries are
reduced to one when the file is loaded. A bare package and a user-specific
target may coexist. App
labels, partial names, and wildcards are not accepted. TrickyStore's `!`
generate suffix is not interpreted. Invalid selectors reject the configuration;
a failed reload keeps the previous valid settings active.

The embedded WebUI presents an icon, application name, package name, and
selection control for each installed package. Multiple Android users have
separate groups, but package selections apply to every user of the same package.
Manual selection, recommended selection and system-app checkboxes automatically
persist plain package names without user suffixes. When a selection is saved,
existing package@user selections are converted to plain package names and
deduplicated; explicit UID entries remain intact. Opening the picker alone
does not migrate configuration. SOTER identity assignments remain independent
and keep their exact package/user scope. A WebUI save merges the user's additions
and removals into the current normalized `scoop` list;
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
including when the WebUI is closed. If one or more new packages appear in the
same scan, it adds only the package whose APK has the newest installation
timestamp as a plain package target without a user suffix; the other packages are
recorded in the baseline but remain unselected. System applications are
excluded. App updates and unchanged installed apps do not re-add a manually
deselected target. Disabling the option leaves
existing selections unchanged and cancels earlier unfinished enable requests
and package scans. Enabling it again records a fresh baseline; applications
installed while disabled are not added in bulk. The WebUI reads back the saved
switch after a change; an unsuccessful or superseded save requires reloading
the current setting before another toggle.
The switch and per-user package snapshots are stored in
`/data/misc/keystore/omk/data/auto_targets.json`. An unreadable user profile keeps
its previous snapshot; the same state file stores a switch generation to reject
stale background work. A newly discovered profile is baselined on its first
successful scan. The background worker checks at approximately one-minute
intervals and on relevant package-list changes, so detection is not immediate.

Android can assign several packages the same identity. In that case, listing
any one of those packages allows the shared identity, unless a filter rule
rejects one of the packages in the group. Adding or removing a package does not
move or convert keys between System and OMK; an app may lose access to keys it
created through the other route.

Key descriptors, including `KEY_ID` and `GRANT`, do not change the selected
backend. A caller must pass the filter and enable the relevant intercept route
to use OMK, including when using a key shared by another app.

Isolated and app-zygote processes use their host application's package identity
for scoop and deny-list decisions. The host is resolved from ActivityManager's
process records and checked against the caller's PID and isolated UID for each
request. SDK sandbox processes, and PCC processes on Android 17, use Android's
host-UID mapping for the same filtering decision.

The original caller UID, PID, and SID are preserved for key access checks.
An isolated process still needs a grant to use its host's keys; host membership
does not confer key ownership. If the host cannot be resolved, the existing
`allow_unknown_package` policy applies. Holding a grant does not bypass scoop.

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

#### `system_app_contexts`

This map is a narrowly scoped exception for an application that runs under the
shared Android system UID. A caller is accepted only when its full process name,
Binder SELinux SID and an entry in `scoop` all match. The default contains only
`com.oplus.engineermode = "u:r:engineermode_app:s0"`, allowing supported Oplus
EngineerMode builds to use OMK for Attestation Key requests. Other UID-1000
processes, including `system_server`, remain on System.

An explicit empty map disables the exception. Do not add a binding without
verifying the exact process name, UID and Binder SID on the target firmware.
Changing this map is hot-reloaded with the rest of `injector.toml`; it does not
migrate keys between System and OMK.

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
process start time before and after the lookup. Procfs identity reads temporarily
use root credentials on the helper's current thread so restricted proc mounts
remain readable; the original SYSTEM identity is restored before ActivityManager
or telephony Binder calls. Monitor and Binder worker threads keep their existing
credentials. Failure to restore the read thread's identity terminates the helper
instead of issuing a request under the wrong UID. Only the process package list
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

An operation selected for OMK returns its OMK business result or an
AOSP-compatible error. A confirmed missing, disconnected, or dead OMK backend
may preserve an available original System reply. Other transport, parcel, or
injector failures do not fall back to a successful System result. There are no
request retries; a later independent request may establish a new connection.

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
changes, restart the injector and reopen the affected app when a clean boundary
is needed after a route change. A syntax error, an unknown field, or an
unsupported future `version` leaves the last valid runtime configuration
active; if present at injector startup, it leaves OMK request routing disabled
until the file is corrected.

The embedded WebUI can change `scoop`, install a locally selected keybox,
synchronize the four `[trust]` patch-level fields from the official Android
Security Bulletin, restore those fields to `"auto"`, manage the validated PIF
profile
fingerprint path. Security-patch sync and restore also manage
the two global runtime properties and the defaults snapshot described above.
Persistent native save paths validate the complete candidate before writing and
use atomic replacement. Successful saves enter the applicable watcher hot-reload
path.

## Oplus engineering key-state display

The existing Zygisk payload loads an app-local Java display bridge only in the
exact com.oplus.engineermode main process. Other app-data directories and
subprocesses are excluded. LSPlant hooks SecurityInterface.isGoogleKeyImport
before Instrumentation.callApplicationOnCreate, using the real app ClassLoader.
The root companion
queries the injector's current parsed configuration for every status check.
An explicitly selected package, package@user or UID with enabled main/filter
and permitted system-app/deny policy returns true for this display check.
When unselected, disabled, denied or unreadable, it invokes the original Java
check. The companion never returns private configuration or key material.
The local SOTER switch and PIF profiles do not control this display bridge.

After specialization it obtains
vendor.oplus.hardware.cryptoeng.ICryptoeng/default through ServiceManager.
Only synchronous BinderProxy.transactNative code 1 calls on that exact Binder
object, with non-null request and reply Parcels, receive a synthetic status 0
and four zero bytes only while that same app-selection policy permits the
override. Other Binders, methods and one-way calls retain their
original behavior. An unavailable service leaves the application unchanged;
JNI reply failures propagate as errors rather than reporting success.

This only changes the engineering application's displayed key-state result.
It does not repair, install or verify a hardware Attestation Key and cannot
establish TEE health. It requires Zygisk and a new engineering-app process
using the updated module. No new persistent state is created.
The Java callback DEX is embedded in the bridge library and loaded
through InMemoryDexClassLoader. libomk_engineer.so contains LSPlant and the
pinned Dobby/LLVM C++ runtime and is loaded through the module directory FD
before app specialization. The engineering application domain may use only its
inherited Zygisk Unix stream via the module policy; SELinux remains enforcing.
It changes no APK or global KeyMint validation.
The module policy grants engineermode_app the keystore2_key gen_unique_id
permission required by the engineering application's INCLUDE_UNIQUE_ID
attestation test. The standard unique-ID permission gate remains intact;
ordinary app domains do not receive this permission. Policy is installed with
the module, independently of its app-local display override selection.
Changing selection takes effect on the next check without reinstalling the
bridge; installing a new bridge requires refreshing the Zygisk module image.
Building the bridge requires NDK r30, CMake 3.28 or newer with Ninja, JDK 9 or
newer with javac --release 8, and Android Build Tools 35.0.0. The normal Cargo
build invokes scripts/build_engineer_bridge.py; the module packager includes
the resulting native library and dependency licenses. Initial dependency
downloads are checksum-verified and subsequent builds use the target cache.

## Local SOTER identities

Tools > Local SOTER identities manages a separate local software identity
store. Add generates a random 16-byte-format device ID (eight leading zero
hex characters and 24 random hex characters) and a new RSA-2048 ATTK using
BoringSSL. Each identity has an independent ledger with per-UID ASK/AuthKey
material, counters and sessions. No private key is returned to the WebUI.
Fresh installations have no predefined identity. Each user creates random
identities explicitly with Add; opening this page does not generate one.

Use the app row's SOTER settings to assign an identity to one exact
package@Android-user target, independently of KeyMint scoop selection. A
32- or 36-character hexadecimal CPU-ID override is optional. Device ID replies
return the decoded 16/18 bytes; ASK/AuthKey exports use the same hex value.
Changing an app's CPU-ID clears only that caller's ASK/AuthKey and sessions
within that identity; counters are preserved. Unselected apps use stock SOTER.
Shared UID packages must agree on their complete identity and override policy;
ambiguous shared UIDs are not taken over.

The master switch defaults off. Turning it off retains local identities and app
assignments, while newly observed requests use the original SOTER path.
Configuration errors do not select another identity. Local keys are software
keys, and CPU-ID is a SOTER protocol field, not a physical CPU modification.
Factory ATTK provisioning operations remain native. The current local broker
does not supply verifiable biometric evidence, so finishSign returns -26. This
identity implementation cannot currently complete fingerprint-payment signing.

The native root supervisor injects only the exact ARM64
com.tencent.soter.soterserver process and intercepts supported vendor HAL
requests during the selected app's Binder call. This requires a working
Tencent service and a supported vendor AIDL/HIDL path. A saved switch or
generated identity does not establish device support or payment acceptance.
Private transport sockets retain the target SoterServer's SELinux MLS range
and categories with the system_file socket type. Socket creation context is
thread-local and restored after each operation; SELinux stays enforcing.

All new SOTER data is root-owned under
/data/misc/keystore/omk/data/soter/ with directory mode 0700 and file mode
0600. identities.json stores public identity metadata and app policy. Each
opaque identity ID names a private JSON ledger. Adding an identity is explicit;
opening the dialog creates no files. No remote relay, imported factory private
keys or application-preference clearing is part of this feature.

The package picker's menu offers bulk identity assignment. It snapshots all
checked installed package/user entries, including system apps, independently
of the visible search results. The user selects an existing identity and
confirms before one atomic policy write. Existing assignments and CPU-ID
overrides are retained, and the SOTER master switch is unchanged. Missing
identity, invalid target, or the 512-entry limit rejects the whole update.
Unavailable packages and raw UID rules without a checked package row are not
expanded into inferred app identities. A new package selection after opening
the dialog is not included until the bulk dialog is reopened.

Each identity has a Delete action with explicit confirmation. Deletion removes
its private ledger (including keys and sessions) and all app assignments to that
identity; those apps return to stock SOTER. Other identities and KeyMint Keybox
data are unchanged. Deletion cannot be undone. Policy is revoked before the
private ledger is unlinked; an unlink failure is reported and can be retried.

Root helper commands are --webui-get-soter-local and
--webui-set-soter-local-base64. The latter accepts a bounded Base64 JSON
change: enabled, add, remove (identity ID), app, or apps (identity ID and target
array, preserving existing assignments). Encoded management commands are
bounded to 120 KiB. Master state, identity creation and app saves
are independent changes serialized with the private directory lock.

## Local RKP Keybox issuance

**Issue local RKP Keybox** is separate from **Fix RKP**. It generates a
software P-256 private key locally and requests a certificate for its public
key using this device's RKP evidence. The key is
not TEE-backed. This does not repair TEE, enable fingerprint payment, restore
factory provisioning, or guarantee a Play Integrity verdict.

The WebUI offers Auto, V2 native, V1 AIDL and V1 native protocols. Auto attempts
V2 native, V1 AIDL, then V1 native when the required local resources exist.
Qualcomm SoC evidence is required for both native protocols. MediaTek devices
use V1 AIDL only; the bridge recognizes both `rkpdapp.apk` and
`rkpdapp.google.apk` inside the system RKP APEX.
Only local CSR construction failures permit trying another protocol. The V1
AIDL route uses the device's system RKP proxy in an isolated Java `app_process`
bridge. The native routes use the device's Qualcomm KeymasterUtils library in
an isolated child process. Resource presence is not proof of vendor ABI or
firmware support. V1 depends on the HAL accepting the upstream PureSoft or
native MAC construction; it is not a universal Android provisioning API.
V2 verifies the CSR/DICE signatures, structure, challenge and generated public
key binding. V1 encrypted evidence can only be validated fully by the server.

Every issuance requires a separate confirmation. The helper sends the real
`ro.build.fingerprint` (or an explicit per-issuance override), generated public
key and device RKP evidence only to
`https://remoteprovisioning.googleapis.com/v1:fetchEekChain` and
`https://remoteprovisioning.googleapis.com/v1:signCertificates` over verified
HTTPS. It never uploads the software private key. Redirects and automatic
signing retries are disabled. A timeout, malformed response or failed save
after submission must not be treated as permission to retry blindly.
Each network operation is bounded to 30 seconds and 256 KiB of response;
each local bridge/worker is bounded to 30 seconds.

**Include build fingerprint in signing request** is off by default. The
effective fingerprint is always sent when fetching the challenge; this option
also adds it as unverified metadata in the signing CSR. V1 places it in the
unverified DeviceInfo map and V2 appends a fifth AuthenticatedRequest field.
Signed and encrypted evidence retains its original bytes. Metadata is not
covered by the hardware signature and must refer to the same firmware build
as the device evidence's VBMeta digest. A per-issuance fingerprint override
applies consistently to challenge fetching and all local protocol candidates.
The choice never changes automatically after errors. Values are bounded to
1024 UTF-8 bytes without control characters. These options are not persisted.

Issued chains must match the generated key and pass certificate validity,
issuer signature, CA/path-length/key-usage and pinned Google root checks.
Successful issuance stores `data/rkp-artifacts/<id>/keybox.xml` under the OMK
root (`/data/misc/keystore/omk/`), with root-owned 0700 directories and a 0600
file. The XML contains the software private key; no duplicate private-key
file is written. At most 16 results are retained; issuance refuses when full,
and does not delete older results automatically. Temporary bridge files are
removed after the request. Opening the list creates no state and returns only
an opaque ID, Unix creation timestamp and certificate subjects, never XML,
private keys, CSR contents or device identifiers.

Issuance does not change the active Keybox. **Import** requires another
confirmation, revalidates the stored chain, and uses the existing local
Keybox installation path. Its replacement/hot-reload and existing-key
semantics are the same as ordinary local import. Expired results can still be
listed, but cannot be imported. Importing a local result does not change other services
or ordinary OMK package-routing settings.

Root-only helper commands:

```sh
keymint --webui-rkp-issue --confirm-issuance auto
keymint --webui-rkp-list
keymint --webui-rkp-import <32-lowercase-hex-id> --confirm-replace
```

The optional protocol argument accepts `auto`, `v1`, `v2`, or `v1-native`.
Add `--include-fingerprint` to include unsigned CSR metadata, and optionally
`--fingerprint-base64 <standard-base64-utf8>` to override the build fingerprint
for this issuance. Without an override the current device property is read
when issuing. The WebUI confirmation displays both choices before submission.
Browser previews never execute these commands. Android arm64 is required;
device and Google server acceptance must be tested on the actual firmware.
The inherited V2 DICE validator recognizes Android 14, 15 and 16 profiles;
an unknown future profile is rejected, not assumed compatible.

The arm64 build embeds a DEX JAR compiled from `runtime/rkp/RkpV1Bridge.java`.
Building requires the repository's nightly Rust toolchain, a JDK with
`javac --release 8`, and Android SDK Build Tools containing `lib/d8.jar`.
Set `JAVA_HOME` and `ANDROID_HOME` (or `ANDROID_SDK_ROOT`) when not discoverable.
`ANDROID_BUILD_TOOLS_VERSION` can select an installed Build Tools version.
The bridge uses reflection against the device's system RKP APK, not bundled
vendor Binder definitions or a downloaded APK.
