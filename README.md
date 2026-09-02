# Oh My Keymint

[![Telegram](https://img.shields.io/static/v1?label=Telegram&message=@OhMyKeymint&color=0088cc)](https://t.me/OhMyKeymint)  [![CI Build](https://github.com/qwq233/OhMyKeymint/actions/workflows/ci.yml/badge.svg)](https://github.com/qwq233/OhMyKeymint/actions/workflows/ci.yml)

Custom keystore implementation for Android Keystore Spoofer

## What is this?

This is a complete implementation of the keystore, which fully implements the AOSP AIDL interface, referencing the official AOSP implementation.

In theory, this would make it harder for detectors to identify behavior inconsistent with AOSP, thus achieving greater stealth than the FOSS branch of TrickyStore or other TrickyStore-based module like TEESimulator.

## Install and configure

**Android 12 or above required.**

1. Install this module.

2. [Configure OMK](docs/CONFIGURATION.md) if needed.

3. Replace template keybox.xml (if you need)

The keybox file must contain at least one complete RSA or EC entry, and every
private key present must match its certificate chain. A keybox may contain both
algorithms or only one; RKP-extracted keyboxes are legitimately EC-only. Keep
the XML free of extra content such as watermarks or invisible characters. The
embedded WebUI can install a replacement through Android's standard file
picker.

The active files are `/data/misc/keystore/omk/config.toml` and
`/data/misc/keystore/omk/injector.toml`. Read the
[Configuration Guide](docs/CONFIGURATION.md) for complete annotated examples,
field-by-field explanations, safety notes, and restart requirements.

In `injector.toml`, keep the `scoop = [` and closing `]` lines, then add each
exact package name on its own line. Bare entries omit both quotes and commas;
blank lines and lines beginning with `#` are ignored. The traditional quoted,
comma-separated TOML form remains accepted.

## Embedded WebUI

The module includes a WebUI for choosing the exact packages in `scoop`,
installing a local keybox, managing the Android security patch level, and
applying a Pixel PIF fingerprint through OMK's own Zygisk payload:

- In KernelSU, open Oh My Keymint from the module list and select its WebUI.
- In Magisk, run the module action. This requires KSUWebUIStandalone or WebUI X
  to be installed already. The action does not download or install a WebUI
  host.

The WebUI uses bundled assets for normal operation. **Sync security patch**
uses the module's native HTTPS client to download the Android Security Bulletin
overview from Google's official `source.android.com` host (with its official
Chinese mirror as a fallback), parses the newest published patch level, and
sends that exact date to the native helper. It does not require `curl` or
`wget` on the device. TLS uses the client's embedded WebPKI roots, and HTTPS
redirects are accepted only when they end at the official bulletin page.
Before the first sync, the
helper records the current `ro.build.version.security_patch` and
`ro.vendor.build.security_patch` values in
`/data/misc/keystore/omk/data/security_patch_defaults.toml`. Later syncs keep
that original snapshot. Each sync writes the published date to all four
`[trust]` patch-level fields and applies it to both runtime properties with
`resetprop`. While that valid snapshot remains, keymint reapplies the paired
property values at startup. A manually configured exact date without the
snapshot continues to use the normal configuration behavior.

**Restore default security patch** does not use the network. It restores both
runtime properties from the saved snapshot, sets `security_patch`,
`os_patchlevel`, `vendor_patchlevel`, and `boot_patchlevel` to `auto`, and then
deletes the snapshot. These runtime properties are global for the current boot,
so other processes can observe the synchronized or restored values. A failed
operation is reported, property writes are rolled back when a later step fails,
and a snapshot needed for another restore attempt is retained.

**Spoof PIF fingerprint** downloads the current Pixel device catalog and the
selected profile from the `bot` branch of `KOWX712/PlayIntegrityFix`. That feed
is generated daily from Google's Android preview pages, Android Flash Tool
metadata, and Pixel security bulletin. The native helper validates the
catalog, the four profile fields, and the complete fingerprint structure. It
then derives the matching Build fields and atomically stores the active profile
at `/data/misc/keystore/omk/data/pif_fingerprint.json`. OMK's own Zygisk
payload applies these values only inside a newly started
`com.google.android.gms.unstable` process through the Zygisk Next loader. Zygisk
Next must already be installed and enabled by the user; OMK does not bundle,
install, or implement that loader. The
selected values are not global Android properties and do not change OMK's
`[device]` identity. Disabling the action removes the OMK profile and restarts
the affected processes so their next instances use the original Build values.

Both network actions use the bundled native HTTPS client and require neither
`curl` nor `wget`. Other WebUI operations remain local. The WebUI can also read
and replace `scoop` and select a local XML file through Android's standard file
picker to replace the active keybox. The security-patch actions do not change
secrets, identity fields, or other settings.

Saving `scoop` is delegated to the native `inject` helper, which validates the
current configuration and package names before atomically replacing
`injector.toml`. Installing a keybox is delegated to the native `keymint`
helper. That helper checks the size, decodes UTF-8, and performs the complete
in-memory `KeyBox` validation before atomically replacing the canonical
lowercase `/data/misc/keystore/omk/keybox.xml`. A failed read, size, UTF-8,
validation, or write leaves the corresponding active file unchanged. The
appropriate watcher loads a successful change automatically, so a restart is
normally unnecessary.

Third-party source and licensing details for the adapted WebUI are listed in
[Third-Party Software](docs/THIRD_PARTY.md).

## Restarting keymint and injector

The module ships two background daemons: one for `keymint`, one for `injector`.
You can restart them by following commands.

```sh
touch /data/adb/omk/restart.keymint
touch /data/adb/omk/restart.injector
touch /data/adb/omk/restart.all
```

See the [Configuration Guide](docs/CONFIGURATION.md#how-changes-are-loaded) for
which changes need a component restart or a full device reboot.

## License

**YOU MUST AGREE TO BOTH OF THE LICENSE BEFORE USING THIS SOFTWARE.**

`AGPL-3.0-or-later`

```plaintext
OhMyKeymint - Custom keymint implementation for Android Keystore Spoofer
Copyright (C) 2025 James Clef <qwq233@qwq2333.top>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

`Oh My Keymint License`

```plaintext
1. 您不得将本软件、本软件的任意部分或将本软件作为依赖的软件用于任何商业用途。该
   商业用途包括但不限于以盈利为目的，将本软件、本软件的任意部分或将本软件作为依
   赖的软件与其他资源、物品或服务捆绑销售。

2. 您不得暗示或明示本软件与其他软件有任何从属关系。

3. 未经本软件作者书面允许，您不得超出合理使用范围或协议许可范围使用本软件的名称。

4. 除非您所在的司法管辖区的适用法律另行规定，您同意将纠纷或争议提交至中国大陆境
   内有管辖权的人民法院管辖。

5. 本协议与GNU Affero General Public License（以下简称AGPL）共同发挥效力，
   当本协议内容与AGPL冲突时，应当优先应用本协议内容，本协议仅覆盖本软件作者拥有
   完全著作权的部分，对于使用其他协议的软件代码不发挥效力。
```

## Credit

Some code from [AOSP](https://source.android.com/)

License: `Apache-2.0`

```plaintext
Copyright 2022, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
