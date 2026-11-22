# Super Amap release and diagnostics

This directory contains the project's release manifest tooling, diagnostic receiver and Android client components. The repository can be used without OEM assets or any collected vehicle data.

## Local verification

Python 3.11 or later is required. Install `requirements.txt`, then run `python -m unittest discover -s . -v`. The test uses a generated TLS certificate, a synthetic event and a temporary database.

`release_manifest.py` generates and verifies detached RSA-SHA256 release metadata. It needs the Android SDK's `apksigner.jar`. The release URL must use HTTPS. The verifier checks the signature on the manifest, SHA-256 and size of the APK, package name, current and offered version codes, and the APK signing identity on Android API 27. Back up the APK signing key and the release metadata key independently. An already distributed key or its passphrase does not belong in Git history.

## Integration

The Android sources implement HTTPS lookup and download, update verification against the installed package, and a private on-device batch spool. App integration still needs enrollment, a background scheduler, a user-confirmed installer entry point, and runtime validation on the target head unit.

The diagnostic receiver listens on loopback. Pair each device with a unique bearer and configure only its SHA-256 digest in the receiver registry. Use a private TLS ingress with an upload limit and rate limiting. A successful response acknowledges a batch only after the SQLite transaction commits. The uploader retains batches after interruptions and the receiver deduplicates retries. The receiver accepts only junction diagnostic rows. It does not accept arbitrary logcat, GPS data or screenshots.

This public GitHub repository contains tooling and synthetic tests. Vehicle diagnostics are sent only to a separately configured, authenticated HTTPS receiver. An authorized release asset or a legally suitable test APK can be supplied separately for an update integration run.

## code157 pre-release

[Download the code157 APK](https://github.com/i6941/super-amap/releases/download/v0.20.1-code157/super-amap-code26000157.apk).
The application ID is `com.aaronlab.superamap` (versionCode `26000157`).

The APK uses the project's local test signing identity. APK Signature
Scheme v2 verified at Android API 27. Clean installation and cold launch
were checked on Android 14 in an emulator. Head-unit validation is pending.

[Build report](releases/code157.json) and
[application ID build script](tools/build_release_identity.py). The script
requires the project build helpers and the exact code153 baseline APK, which
the source tree does not bundle.
