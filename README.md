# 超级高德 · 广汽埃安 LX

**[下载主包和转接包（GitHub Releases）](https://github.com/i6941/super-amap/releases)**

[埃安 LX 改造笔记和排错经验](docs/aion-lx-engineering-notes.md)

## Release and diagnostics tooling

This directory contains the project's release manifest tooling, diagnostic receiver and Android client components. The repository can be used without OEM assets or any collected vehicle data.

## Local verification

Python 3.11 or later is required. Install `requirements.txt`, then run `python -m unittest discover -s . -v`. The test uses a generated TLS certificate, a synthetic event and a temporary database.

`release_manifest.py` generates and verifies detached RSA-SHA256 release metadata. It needs the Android SDK's `apksigner.jar`. The release URL must use HTTPS. The verifier checks the signature on the manifest, SHA-256 and size of the APK, package name, current and offered version codes, and the APK signing identity on Android API 27. Back up the APK signing key and the release metadata key independently. An already distributed key or its passphrase does not belong in Git history.

## Online updates

The code168 release adds a **超级高德更新** launcher entry. It checks Super Amap and the installed LX relay independently. A stock Amap installation is skipped because the relay check requires the relay settings component. A download starts only on request, and Android's package installer asks for confirmation.

The client reads a signed JSON manifest and its detached signature from `updates/` on the `main` branch:

| Package | Manifest | Signature |
| --- | --- | --- |
| Super Amap | `com.aaronlab.superamap.json` | `com.aaronlab.superamap.sig` |
| LX relay | `com.autonavi.amapauto.json` | `com.autonavi.amapauto.sig` |

Checks prefer GitHub Raw and fall back to GHFast (`ghfast.top`) and GHproxy (`ghproxy.net`). The update screen shows which route supplied the manifest. The signed manifest binds the package, version, APK signing certificate, size and SHA-256 to an HTTPS asset URL in this repository. APK downloads use the GitHub Release asset and retry through the same providers.

The manifest signing key is an RSA-3072 key kept outside this repository. Never commit the private key or its passphrase. Keep an independent backup: losing it means a new APK must embed a new public key, and users must install that build manually once.

The diagnostic receiver listens on loopback. Pair each device with a unique bearer and configure only its SHA-256 digest in the receiver registry. Use a private TLS ingress with an upload limit and rate limiting. A successful response acknowledges a batch only after the SQLite transaction commits. The uploader retains batches after interruptions and the receiver deduplicates retries. The receiver accepts only junction diagnostic rows. It does not accept arbitrary logcat, GPS data or screenshots.

This public GitHub repository contains tooling and synthetic tests. Vehicle diagnostics are sent only to a separately configured, authenticated HTTPS receiver. An authorized release asset or a legally suitable test APK can be supplied separately for an update integration run.

## GAC AION LX release

The release targets the GAC AION LX (广汽埃安 LX). Install the
[Super Amap APK](https://github.com/i6941/super-amap/releases/download/v0.20.4-code168/super-amap-code26000168.apk)
first. Its application ID is `com.aaronlab.superamap` (versionCode `26000168`).
Install the optional
[head-unit relay APK](https://github.com/i6941/super-amap/releases/download/v0.20.4-code168/aion-lx-amap-relay-code573.apk)
to route the factory desktop navigation entries and voice commands to Super
Amap. See the [release notes](https://github.com/i6941/super-amap/releases/tag/v0.20.4-code168)
for the prerequisites for updating the factory navigation app.

The first code168 installation is manual. After that, open
**超级高德更新** on the head unit to check both packages online and confirm the
system installer. A parked check on the AION LX downloaded and verified code168
through the in-app entry; the head unit now runs code168 and the update screen
reports both packages up-to-date. The vehicle owner confirmed testing on a GAC
AION LX head unit. The APK signatures were verified at Android API 27. The
code573 relay targets the release application ID and passed offline checks.

[Build report](releases/code168.json) and
[application ID build script](tools/build_release_identity.py). The script
requires the project build helpers and the exact code153 baseline APK, which
the source tree does not bundle.
