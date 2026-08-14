<p align="center">
  <h1 align="center">TEESimulator-RS</h1>
  <p align="center"><b>Pass hardware security checks on a rooted Android phone</b></p>
  <p align="center">
    <a href="https://github.com/Enginex0/TEESimulator-RS/actions/workflows/build.yml"><img src="https://github.com/Enginex0/TEESimulator-RS/actions/workflows/build.yml/badge.svg" alt="Build"></a>
    <img src="https://img.shields.io/badge/Android-10%2B-green?logo=android" alt="Android 10+">
    <a href="https://t.me/superpowers9"><img src="https://img.shields.io/badge/Telegram-community-blue?logo=telegram" alt="Telegram"></a>
  </p>
</p>

---

> [!NOTE]
> This is a fork of [JingMatrix/TEESimulator](https://github.com/JingMatrix/TEESimulator). It adds certificate generation written in Rust, generated keys that survive reboots, and attestation behavior that matches stock Android. See the upstream repo for the original project.

## What it does

Some Android apps refuse to run on a rooted phone. They ask the phone to prove it still has a genuine security chip, a check called hardware attestation. A rooted phone normally fails that check.

TEESimulator makes it pass. Android runs a system process named `keystore2` that answers these proof requests. TEESimulator sits in front of `keystore2`, watches for the requests apps make to create keys and read their certificates, and builds the proof itself: a full chain of certificates signed by your `keybox.xml`. To the app, the phone looks genuine.

It replaces TrickyStore and its forks completely. It reads config from the same files, so you can switch without moving anything, but the internals are rewritten: certificates are generated in Rust, keys are saved across reboots, and each app gets its own limit on how fast it can request hardware-backed keys.

## Requirements

> [!IMPORTANT]
> You need a valid `keybox.xml`. This is the file used to sign the proof. Without it, TEESimulator can only produce software-only certificates, which strict apps reject.

1. Android 10 or newer
2. A root manager: KernelSU, Magisk, or APatch
3. A `keybox.xml` file at `/data/adb/tricky_store/keybox.xml`

## Quick start

1. Download the latest ZIP from [Releases](https://github.com/Enginex0/TEESimulator-RS/releases).
2. Install it with your root manager, then reboot.
3. Put your `keybox.xml` at `/data/adb/tricky_store/keybox.xml`.
4. List the apps you want to cover in `/data/adb/tricky_store/target.txt`.
5. Check that it works with Play Integrity or the Key Attestation Demo app.

## How it works

```
   App
    |  asks the phone to prove it has real security hardware
    v
+----------------------------------------------------+
| keystore2  (the Android process that answers)      |
|                                                    |
|   ioctl  <- TEESimulator hooks the call here       |
|     |                                              |
|     v                                              |
|   builds a certificate chain and signs it          |
|   with your keybox.xml                             |
+----------------------------------------------------+
    |  the signed chain goes back to the app
    v
   App  ->  sees a genuine, hardware-backed device
```

**Certificate generation in Rust.** A native library, `libcertgen.so`, builds the X.509 certificate chains in Rust with the `ring` crypto library, encoding the bytes by hand in DER, the standard certificate format. Three key types fall outside `ring`'s support (the P-224, P-521, and Curve25519 curves); for those it falls back to Java's BouncyCastle.

**Hooking keystore2.** Inside the `keystore2` process, TEESimulator redirects `ioctl`, the low-level system call Android uses to pass messages between processes. It does this with `lsplt`, a hooking library. From there it can read and answer three kinds of request: creating a key, importing a key, and fetching a key's certificate.

**Matching stock Android.** The output matches what a real device produces. Keys that are not attested get self-signed certificates. The fields inside the attestation record keep the same order. Fields that only exist on certain Android versions appear only on those versions. The same usage checks run before a key is used.

**Keys that survive reboots.** Generated keys are written to disk and stay valid after a restart. File locking stops two writers from corrupting the store.

**Per-app rate limit.** Each app may request at most 2 hardware-backed keys per 30 seconds, and only 2 at a time. Past that, it receives a software-only certificate.

## Configuration

All config files live in `/data/adb/tricky_store/`. TEESimulator reloads them the moment you save, so a reboot is not needed.

### target.txt

Lists the apps TEESimulator handles, one package name per line. A suffix sets how each app is handled.

| Suffix | What it does |
|--------|--------------|
| `!` | Always make a software key |
| `?` | Keep the real hardware key, patch only its certificate |
| none | Decide automatically |

To use more than one keybox, add a `[filename.xml]` header above the apps that should use that file:

```
com.google.android.gms!
io.github.vvb2060.keyattestation?

[aosp_keybox.xml]
com.google.android.gsf
```

### security_patch.txt

Sets the security patch dates reported in the attestation certificates. Global defaults go at the top. Override them for one app with a `[package.name]` header.

| Key | What it sets |
|-----|--------------|
| `system` | OS patch level |
| `vendor` | Vendor patch level |
| `boot` | Boot and kernel patch level |
| `all` | All three at once |

Accepted values: `today`, a `YYYY-MM-DD` template, `no` to omit the field, `device_default`, or `prop` to read the value from a system property.

```
system=YYYY-MM-05
vendor=device_default
boot=no

[com.google.android.gms]
system=2025-10-01
```

### boot_props_mode

Controls global `ro.boot.*` property spoofing. Values: `auto` (default), `force`, or `disable`.

In `auto`, Oplus-family devices (OnePlus/OPPO/realme/Oplus) skip boot-state prop spoofing to avoid conflicts with vendor TEE services such as ultrasonic fingerprint calibration. Create `/data/adb/tricky_store/boot_props_mode` with `force` to restore the old behavior, or `disable` to turn it off on any device.

## Building from source

You need JDK 21, the Android SDK and NDK 29, Rust (stable) with the `aarch64-linux-android` target, and `cargo-ndk`.

```bash
git clone --recursive https://github.com/Enginex0/TEESimulator-RS.git
cd TEESimulator-RS
./gradlew zipRelease zipDebug
```

The ZIPs land in `out/`. Gradle runs `cargo ndk` for you to cross-compile `libcertgen.so`. To build on CI instead, push to `main` or run Actions > Build > Run workflow.

## Compatibility

| Root manager | Status |
|---|---|
| KernelSU | Tested, including the Action button and lifecycle scripts |
| Magisk | Supported |
| APatch | Supported |

## Community

<p align="center">
  <a href="https://t.me/superpowers9">
    <img src="https://img.shields.io/badge/SuperPowers_Telegram-Join-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>
</p>

## Credits

- [JingMatrix](https://github.com/JingMatrix/TEESimulator) for the original TEESimulator and its interception design
- [ring](https://github.com/briansmith/ring) for the Rust cryptography
- [fatalcoder524](https://github.com/fatalcoder524) for contributions and collaboration
- [huguangares](https://github.com/huguangares) for collaboration and testing

## License

[GNU General Public License v3.0](LICENSE)
