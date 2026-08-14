> [!NOTE]
> The project is going through a heavy refactor at the moment, so public commits may lag behind for a while.

---

## TEESimulator-RS v6.0.1-307

Fixes five gaps in the module's TEE key-operation and attestation emulation. Two of them fix crashes in real app crypto on a broken-TEE device: any app using an AndroidKeyStore HMAC key or an RSA-OAEP-SHA256 key was throwing. This is a beta; the confirmation logs are in the debug build only, and nothing is field-verified yet.

### App crypto correctness
- HMAC operations now run instead of throwing. An AndroidKeyStore HMAC key is symmetric, so an HMAC SIGN fell into the asymmetric SIGN path and failed on a null key pair, and no MAC primitive existed. SIGN and VERIFY now work: the tag is computed with Mac (HmacSHA256/384/512), truncated to the requested MAC_LENGTH (full digest when unspecified), and checked with a constant-time compare.
- RSA-OAEP-SHA256 decrypt no longer fails with BadPaddingException. The cipher ran with no OAEPParameterSpec, so JCA fell back to SHA-1 and rejected SHA-256 ciphertext. It now applies the correct main and MGF1 digests. A key that authorizes several MGF1 digests uses the one the operation requested, not the key's first.
- Grant-domain attestation keys now resolve. A self-granted PURPOSE_ATTEST_KEY (a Domain.GRANT descriptor) could not resolve its signer alias, so generateKey failed and the subject key was never stored, returning KEY_NOT_FOUND on readback. The grant now resolves to the owner key's alias, and the subject key stays readable under Domain.APP.

### Supplementary attestation
- MODULE_HASH now comes from the framework's own getSupplementaryAttestationInfo, so it matches the value a verifier computes. It falls back to local re-derivation when that API is unreachable.

### Diagnostics (debug builds only)
- New per-operation (oaep-op, hmac-op, attest-grant) and device-level (module-hash, vintf-version) source logs. R8 strips them from release builds.

### 中文说明

修复本模块在 TEE 密钥操作与证明模拟中的五处缺陷。其中两处修复的是真实应用在 TEE 损坏设备上的加密崩溃：任何使用 AndroidKeyStore HMAC 密钥或 RSA-OAEP-SHA256 密钥的应用此前都会抛出异常。本版本为测试版；确认日志仅存在于 debug 构建中，且尚未经过真机验证。

**应用加密正确性**
- HMAC 操作现在可正常执行，不再抛出异常。AndroidKeyStore 的 HMAC 密钥是对称密钥，因此 HMAC SIGN 此前落入了非对称的 SIGN 分支，并因 key pair 为空而失败，当时也没有 MAC 原语。现在 SIGN 与 VERIFY 均可工作：用 Mac (HmacSHA256/384/512) 计算标签，按请求的 MAC_LENGTH 截断（未指定时取完整摘要长度），并用恒定时间比较进行校验。
- RSA-OAEP-SHA256 解密不再抛出 BadPaddingException。此前 cipher 未传入 OAEPParameterSpec，JCA 因而回退到 SHA-1 并拒绝 SHA-256 密文。现在会应用正确的主摘要与 MGF1 摘要。若密钥授权了多个 MGF1 摘要，将使用本次操作请求的那个，而非密钥的第一个。
- Grant 域证明密钥现在可以解析。自授权的 PURPOSE_ATTEST_KEY（Domain.GRANT 描述符）此前无法解析其签名者别名，导致 generateKey 失败且从不存储主体密钥，读取时返回 KEY_NOT_FOUND。现在该 grant 会解析为属主密钥的别名，主体密钥在 Domain.APP 下仍可读取。

**补充证明**
- MODULE_HASH 现在取自框架自带的 getSupplementaryAttestationInfo，因而与验证方计算出的值一致。当该 API 不可用时，回退到本地重新推导。

**诊断（仅 debug 构建）**
- 新增按操作 (oaep-op、hmac-op、attest-grant) 与设备级 (module-hash、vintf-version) 的来源日志。R8 会在 release 构建中将其剥离。

---

## TEESimulator-RS v6.0.1-282

AUTO-mode key attestation now forges plain attestation from the keybox instead of deferring to the real TEE.

### Detection coverage
- AUTO dispatch probed the device with `checkTeeFunctionality`, which only proves the TEE can mint one EC key. It says nothing about RSA attestation, device-ID attestation, or whether a patched chain survives RSA verify. Plain attestation requests (attest-key OFF, challenge present) were routed to PATCH and deferred to hardware, so devices that can't back that surfaced KeyAttestation reds: `ATTESTATION_KEYS_NOT_PROVISIONED` (-49) and `BLOCK_TYPE_IS_NOT_01`.
- AUTO targets carrying an attestation challenge now take the FORGE path, the same one attest-key-ON already used: a synthetic chain built from the keybox and rooted under the Google root key. Requests with no challenge still pass through to real hardware, so KeyDetector's hardware-backed checks are unaffected.

### Verified
- Offline conformance against real FORGE captures: uid10389 and uid10154 chains are GREEN; the root SPKI byte-matches `GOOGLE_ROOT_PUBLIC_KEY`.

---

## TEESimulator-RS v6.0.1-280

Clears the Duck Detector generate-mode parcel fingerprint that real Android 16 hardware also trips, fixes RSA attestation under an EC-only keybox, and restores device-property attestation for Play Integrity hardware apps such as BHIM and UPI. Generate-mode fix field-confirmed on Android 16.

### Detection coverage
- Generate-mode fingerprint: Duck reads the reply at a flat 12-byte stride and flags the sentinel tuple at positions 12 and 13 that the device's native ALGORITHM-first authorization order lands on. Real A16 silicon trips the same probe, so faithful mirroring stayed flagged. `normalizeAuthorizationLayout` marshals the auth array, runs Duck's exact predicate, and applies a minimal deterministic reorder only when it would match. Count, values, security levels, and the cert chain are untouched, and the reorder keys on the byte condition, never on a package. Applied on both the patch and forge reply paths. (#33)
- `updateAad` on a non-AEAD operation now answers per vendor: Samsung and Xiaomi-MTK TEEs return success, others return INVALID_TAG, matching Duck's OperationErrorPathProbe on both the sign/verify and cipher paths.

### Attestation correctness (Android 16, EC and RSA)
- RSA leaf under an EC-only keybox: patching used to catch the no-RSA-key throw and return the chain untouched, leaking the device's real unlocked Root of Trust for RSA keys while EC keys patched cleanly. It now falls back to any keybox key (EC preferred) and signs the patched leaf with the keybox key's own algorithm, so the RSA leaf re-roots to the Google keybox under a forged locked RoT.
- RSA attest-key forge on an EC-only keybox: the forge path matched the algorithm exactly and threw -75 ATTESTATION_KEYS_NOT_PROVISIONED on a miss, so an RSA ATTEST_KEY request never rooted and verifiers reported an unknown certificate. It now falls back to any attestation key, since an EC key validly ECDSA-signs an RSA-subject leaf. No-op on a dual keybox.
- A16 attestVersion: the device's KeyMint reports version 100 and the lazy cache shadowed the BAKLAVA-to-400 map, so the forge presented 100. It now caches the AOSP value per SDK and presents the correct 400.
- Algorithm-split key on restore: a persisted record holding an EC private key under an RSA leaf failed every signature as DATA_TOO_LARGE_FOR_MODULUS. Restore now drops the record when the private key and served leaf disagree, so the next generateKey rebuilds a coherent key.
- Stale chain on regenerate: reusing an alias in generateKey now evicts the cached chain, matching keystore2, so getKeyEntry serves the current key instead of a stale forge from an earlier generation.

### App compatibility
- Device-property attestation (BRAND, MODEL, and the rest) now forges unconditionally. The old gate probed the live TEE, which is dead on every device the module serves, so it rejected GMS Play Integrity's hardware path and broke BHIM and other UPI and Play-Integrity apps. Device-ID attestation (IMEI, serial) stays governed by the real KeyMint caller-permission rule: privileged callers get it, ordinary apps do not.
- getKeyEntry now reaches the owned-key lookup for skipped privileged UIDs, so framework attestKeyAlias resolution no longer returns "Invalid attestKeyAlias" for Key Attestation over Shizuku. Non-owned keys still skip post-processing, so a real app's key is never patched.
- Device-ID attestation over Shizuku (a privileged UID absent from target.txt) now takes the forge path instead of hitting the real TEE's CANNOT_ATTEST_IDS (-66). "Use attest key" no longer double-roots: a reused persistent attest key is resolved by KEY_ID as well as alias, and an unresolved designated attest key refuses to emit a leaf rather than silently re-rooting under the keybox.

### Diagnostics (debug builds only)
- Per-UID attestation dossier for targeted UIDs at /data/local/tmp/teesim/, recording the decoded chain on both forge and patch paths, key params, the keybox pick (including EC fail-safe), prop sources, forge failures, the emitted authorization shape, and served-versus-verified chains. Release builds strip this through R8 and stay silent. Keybox certificate serials log on every fetch for revocation triage.

### Verified
- Android 16: generate-mode fingerprint signal gone, confirmed on device 2026-06-19.

---

## TEESimulator-RS v6.0.1-251

14 commits since v6.0.0-235. Clears the remaining Duck Detector grant-domain rows (incl. the Android 16 OnePlus report), restores Google Wallet and fingerprint compatibility, and removes the in-module patch-level/bulletin resolvers. Test device (SDK 35) TEE tamper score 28 → 8.

### Detection coverage
- Grant plane virtualized: owner read and cross-app `Domain.GRANT` read return one identical chain. 6 RED rows cleared. (28 → 18)
- Generate-mode fingerprint: dropped 2 surplus authorizations (both patchlevels), USER_ID moved to SOFTWARE to mirror a captured device. (18 → 8)
- Android 16 grant: patch-mode keys now served on the grant plane, so owner and grant reads match, fixes CHAIN_SPLIT.
- Grant gated to SDK ≥ 36: Android 15 answers PERMISSION_DENIED, no synthetic over-capability.
- Stale-chain eviction: import and updateSubcomponent drop the cached attestation; no pre-mutation chain replays.
- Lifecycle coherence: clearNamespace / deleteAllKeys / migrateKeyNamespace mirror synthetic key and grant state, defeats delete-then-read probes.
- Device-ID attestation mirrors the real TEE: returns CANNOT_ATTEST_IDS where silicon can't attest, instead of forging it.

### App compatibility
- Google Wallet: INCLUDE_UNIQUE_ID stripped (not rejected) when the caller lacks the permission; card binding works. (PR #27)
- Fingerprint / vendor keys: KEY_ID miss skips the post-handler, so real HAL operations are no longer wrapped and broken. (PR #26)

### Removed
- PatchLevelManager, auto-resolved the security-patch date from an installed PlayIntegrityFix module (with hot-reload) and applied it to props.
- BulletinPoller, scheduled security-bulletin refresh.

### Other
- Release builds purge stale `teesim-*.bin` diagnostics from `/data/local/tmp` at boot.
- Vol-key confirmation rewritten to 1s `getevent` bursts (piped stream missed single presses on Magisk).

### Verified
- SDK 35, Xiaomi 23106RN0DA: tamper 28 → 8; generate-mode signal gone; 4 grant rows UNAVAILABLE (correct for Android 15); no regressions.
- Android 16 grant fix built but unconfirmed on SDK 36, needs an affected OnePlus user to confirm the grant rows clear.

---

## TEESimulator-RS v6.0.0-235

11 commits since v6.0.0-224. Duck Detector generate-mode fingerprint cleared. Shizuku-routed BYO attestation fixed. Vol-key confirmation restored on Magisk.

### Detection Coverage
- Duck Detector "TEE Simulator generate-mode fingerprint" cleared. `toAuthorizations` reordered to AOSP keymint reference order; KEY_SIZE moves from auth#4 to auth#2, breaking the byte-224 anchor the probe relied on. 0/31 matches on fresh self-probes (was 15/36).
- `persist.logd.size` variants blanked at boot via `service.sh`. Removes a logd-tuning side-channel.

### BYO & Shizuku Routing
- Shizuku-routed BYO attestation no longer fails with `-49 UNSUPPORTED_TAG`. `shouldSkipUid` moved into `handleGenerateKey`, evaluated after BYO parameters are parsed.
- `createOperation` parallel fix: outer UID gate removed; the cache-or-forward lookup is the sole gate. BYO keys created under Shizuku UID can now be used for signing under the same UID.
- `forceGenerate` simplified: any attest-key or BYO request routes to software unconditionally.
- BYO attest-key miss returns the full keybox chain instead of a malformed depth-1 chain.
- AUTO TEE race dispatch removed. Resolution uses `DeviceAttestationService.isTeeFunctional` only.
- Symmetric gen rejects `attestationKey != null` early with `INVALID_ARGUMENT`. Unsupported-algorithm branch returns `-38` instead of `-49`.

### Action Button
- Vol+ / Vol- confirmation restored on Magisk. Streaming `getevent -lq` matched inline against `KEY_VOLUMEUP DOWN` / `KEY_VOLUMEDOWN DOWN`, wrapped in `/system/bin/timeout 10`. The prior polled approach timed out on six-events-per-keypress kernels.

### Verified
- Android 15 (SDK 35), daemon PID 1466.
- Cross-device confirmation pending on OnePlus PKX110 and Samsung SM-S928B.

---

## TEESimulator-RS v6.0.0-224

59 commits since v6.0.0-162. Self-sufficient spoofing infrastructure, Duck Detector TamperScore-4 cleared on Xiaomi A16, persistent symmetric key storage (PR #22), 22-language action button hardening.

### Detection Coverage
- Duck Detector TimingSideChannelProbe cleared on Xiaomi A16 (SDK 35). Timing ratio dropped 1.555x to 1.055x, verdict WARNING to CLEAR. Threshold is > 1.1x.
- `KEY_ID` resolved from `teeResponses` instead of synthesized, matching real KeyMint binder behavior.
- Non-attested key cache mirrors attested path for byte-level metadata parity.
- `KEY_SIZE` emitted for EC keys; omitted when `ecCurve` is present, matching AOSP attestation_record.h.
- SSE messages synthesized canonically on non-AEAD `updateAad`; passthrough shape normalized.
- StrongBox attest version no longer hardcoded; resolved from device context.
- TEE op latency floor enforced to defeat micro-timing probes.
- Attest key resolution restored to nspace-aware lookup after revert/restore cycle.

### Self-Sufficient Spoofing
- `PatchLevelManager` resolves OS/VENDOR/BOOT patch levels via PIF without external bulletin fetch.
- `BulletinPoller` refreshes bulletin data on a schedule, isolated from boot path via umbrella `try/catch`.
- Bootloader-lock props pushed via `resetprop` at boot; absent vbmeta complement props filled; `vbmeta.device_state` included.
- PIF hot-reload via `FileObserver`; empty source files skipped; future patch dates bounded by `MAX_FUTURE_DAYS`.
- Default `security_patch.txt` dropped at install time.
- `sepolicy.rule` allows UDP egress for DNS resolution.

### Key Persistence (PR #22)
- Symmetric keys persist across reboots with byte-identical metadata.
- Keybox edits no longer wipe stored keys.
- Delete marker dropped on key regeneration to prevent stale state.
- Defensive symmetric fallback path with clean error codes.

### Reliability
- `atomicWrite` preserves `[pkg]` sections; errors guarded in `updateTo`.
- `applyToProps` serialized against concurrent callers.
- `pollOnce` wrapped in umbrella `try/catch`; `BulletinPoller.start` failure isolated from spoofer init.
- Spoofer ordering fixed: runs before keystore hook to prevent attest-time prop drift.
- `isAutoMode` reads raw package mode; `system=prop` passive default respected.
- `mergedContents` propagates read errors instead of swallowing them.
- Date regex validation on `currentPatch`; YYYY-MM input skips day synthesis.
- Global key-assignment check requires `=` delimiter (no more partial matches).
- `validation_rejected` status emitted on invalid spoof input.

### Action Button UX
- Vol+ required to clear `persistent_keys`. Vol- cancels. 10-second timeout defaults to cancel.
- Confirmation localized in 22 languages: ar, az, bn, de, el, es-ES, fa, fr, id, it, ja, ko, pl, pt-BR, ru, th, tl, tr, uk, vi, zh-CN, zh-TW.
- Every echoed string resolves through `_msg()` against device locale.

### Build & Ops
- Kotlin `jvmTarget` raised to JVM 21.
- Gradle auto-rewrites `module/update.json` on packaging.
- `scripts/package.sh` locates user-local cargo; rust task receives cargo bin path.
- Verified on Xiaomi Android 16 (SDK 35) `v6.0.0-224-Release`. Daemon alive PID 1392. Pending cross-device confirm on OnePlus PKX110 (qcom sun) and Samsung SM-S928B (pineapple).

---

## TEESimulator-RS v6.0.0

Repository consolidation release. All tee-rebuild work merged as the new main branch.

### AOSP Self-Signed Cert Compliance
- No-challenge keys now generate self-signed certs (subject == issuer, depth 1), matching AOSP `ta/src/keys.rs:451-478`
- Both Kotlin (BouncyCastle) and Rust (native-certgen) paths corrected
- Eliminates attestation behavioral probes that detect keybox issuer on non-attested keys

### Stability
- Binder stress crash hardening for concurrent generateKey calls
- AUTO mode TEE race for consistent attestation on devices with working G10
- Oversized transactions routed to software gen instead of crashing
- Operation-time params (BLOCK_MODE, PADDING, DIGEST) passed through to CipherPrimitive

### Banking App Compatibility
- Bare `target.txt` entries now default to AUTO mode, resolved at config level to PATCH (working TEE) or GENERATE (broken TEE)
- Fixes BHIM and similar banking apps that require TEE-backed attestation keys
- Restores v5.0 behavior where AUTO was resolved before the interceptor dispatch, avoiding the non-deterministic `raceTeePatch` path

### Infrastructure
- Version scheme changed to semver (v6.0.0)
- Repository moved to TEESimulator-RS as canonical source

---

## TEESimulator-RS v5.0: AOSP Compliance Overhaul

Major release integrating 30+ AOSP compliance improvements from upstream PR #157 analysis, layered on top of our StrongBox hardening and native cert gen architecture.

### Attestation Extension Alignment
- 17 enforcement tags added to KeyMintAttestation (ACTIVE_DATETIME, ORIGINATION_EXPIRE, USAGE_EXPIRE, USAGE_COUNT_LIMIT, CALLER_NONCE, UNLOCKED_DEVICE_REQUIRED, INCLUDE_UNIQUE_ID, ROLLBACK_RESISTANCE, EARLY_BOOT_ONLY, ALLOW_WHILE_ON_BODY, TRUSTED_USER_PRESENCE_REQUIRED, TRUSTED_CONFIRMATION_REQUIRED, NO_AUTH_REQUIRED, MAX_USES_PER_BOOT, MAX_BOOT_LEVEL, MIN_MAC_LENGTH, RSA_OAEP_MGF_DIGEST)
- BLOCK_MODE encoded as SET OF INTEGER per AOSP attestation_record.h
- Version-guarded tags (RSA_OAEP_MGF_DIGEST >=100, ROLLBACK_RESISTANCE >=3, EARLY_BOOT_ONLY >=4)
- INCLUDE_UNIQUE_ID computed via HMAC-SHA256 per KeyMint HAL spec using device HBK
- AAID gated on attestation challenge presence
- Certificate validity defaults aligned with AOSP (epoch notBefore, 9999-12-31 notAfter)

### Binder Infrastructure
- Native transaction code filtering at C++ level, skipping JNI for non-intercepted codes
- getNumberOfEntries includes software-generated key count
- deleteKey resolves KEY_ID domain via generatedKeys lookup
- patchAuthorizations for OS/VENDOR/BOOT patch levels in authorization arrays

### Software Operation AOSP Conformance
- updateAad on non-AEAD operations returns INVALID_TAG (-76), matching AOSP operation.rs
- All crypto exceptions wrapped as ServiceSpecificException with correct KeyMint error codes
- GCM IV returned in CreateOperationResponse.parameters for encrypt operations
- SoftwareOperationBinder methods @Synchronized, matching AOSP Mutex per operation
- authorize_create enforcement: PURPOSE validation, algorithm-purpose compatibility, temporal constraints, CALLER_NONCE prohibition, WRAP_KEY rejection

### Security and Configuration
- SELinux permission checks via /proc/pid/attr/current
- Per-UID permission verification through IPackageManager.checkPermission
- Imported key tracking prevents stale attest-key overrides in getKeyEntry
- nspace consistency fix in attest-key override path
- TeeLatencySimulator with log-normal distribution matching real hardware profiles
- Device-unique HBK seed generated on install (32 bytes from /dev/random)

### Preserved from v4.8
- StrongBox op limits (4 concurrent max, TOO_MANY_OPERATIONS rejection)
- LRU operation pruning per security level
- Hardware keygen rate limiting (2/30s sliding window, 2 concurrent cap)
- Native Rust cert generation with BouncyCastle fallback
- Key persistence across reboots

---

## TEESimulator-RS v4.8.1: StrongBox Op Rejection Fix

- **StrongBox op limit gate fix**, `trackAndEnforceOpLimit` was only called in the `Domain.KEY_ID` not-found path, so software-generated keys (found via `Domain.APP`) bypassed `STRONGBOX_MAX_CONCURRENT_OPS=4` entirely. DuckDetector's concurrent signing handles test created 24+ operations that all succeeded via LRU pruning instead of being rejected with `TOO_MANY_OPERATIONS (-29)`. Now enforced for all StrongBox createOperation paths.

---

## TEESimulator-RS v4.8: StrongBox Hardening & LRU Pruning

Tested against DuckDetector on OnePlus (Android 16, KSU). Tamper score dropped from 32 to 8.

- **LRU operation pruning**, Concurrent software operations capped at 15 per UID (TEE) and 4 per UID (StrongBox), with oldest-first eviction. Pruned operations return `INVALID_OPERATION_HANDLE (-28)`, matching AOSP keystore2 malus-based pruning.
- **StrongBox param guard**, Unsupported StrongBox params (RSA >2048-bit, non-P256 EC curves) forwarded to real HAL for proper rejection instead of generating in software.
- **StrongBox timing**, Key generation floors at 250ms, signing at 80ms on StrongBox security level to match real secure element latency.
- **StrongBox op limit**, Sliding-window enforcer caps concurrent StrongBox operations for both software and hardware key paths, returning `TOO_MANY_OPERATIONS (-29)` when exceeded.
- **ECDSA algorithm alias**, Accept "ECDSA" in addition to "EC" as JCA private key algorithm name. Fixes SIGSEGV crash on Android 10 devices where the provider reports EC keys as "ECDSA". Closes #4.
- **createOperation domain handling**, Software-generated keys now found via both `Domain.APP` (alias) and `Domain.KEY_ID` (nspace) lookup paths.
- **Permission guards**, Device ID attestation tags (IMEI, MEID, serial) require caller permission checks.

---

## TEESimulator-RS v4.7: Operation & Attestation Fixes

Tested against [KeyDetector](https://github.com/XiaoTong6666/KeyDetector) and [Key Attestation](https://github.com/nickel-lang/nickel) on OnePlus (Android 16) and Xiaomi Redmi 14C (Android 14).

- **PADDING encoding**, Fixed ASN.1 encoding of PADDING tag in attestation extension from individual `[6] INTEGER` entries to `[6] SET OF INTEGER`, matching AOSP `attestation_record.h` schema. Broke all RSA key attestation since v4.6.
- **Operation error-path conformance**, Software operations now track finalized state and return `INVALID_OPERATION_HANDLE (-28)` on post-abort calls. Input length guard (32KB) returns `TOO_MUCH_DATA` matching AOSP `operation.rs`. Passes KeyDetector's OperationErrorPathChecker.
- **updateAad support**, Added `updateAad` to `SoftwareOperationBinder`, fixing `AbstractMethodError` on Android 16 where the runtime Stub declares it abstract.
- **Algorithm inference**, `createOperation` now infers algorithm from the stored key pair when operation params omit the ALGORITHM tag, matching AOSP behavior.

---

## TEESimulator-RS v4.6: Rebrand & Detection Fix

- **RTT normalization rework**, Replaced Gaussian sleep (mean=55ms) with a 15ms floor fence. The old approach triggered Chunqiu Native Check 2.8 timing analysis; the floor-only approach satisfies the minimum RTT threshold without creating a detectable delay pattern.
- **Cross-algorithm attestation**, Signing algorithm now derived from the attestation key's actual type, not the generated key's algorithm. Fixes BouncyCastle crash when signing RSA keys with EC attestation keys (Shizuku attestation flow).
- **Device ID attestation**, Serial/IMEI/MEID/secondImei tags now flow through to software cert gen instead of blanket rejection. Only DEVICE_UNIQUE_ATTESTATION is rejected, matching AOSP keystore2 policy.
- **Rebrand to TEESimulator-RS**, Distinguishes this fork from upstream. Version scheme simplified to v{major}.{minor}-{commitCount}.
- **CI streamlined**, Release pipeline uses Gradle-generated filenames directly, eliminating the rename step.

---

## TEESimulator v4.5: Detection Hardening

Tested against [KeyDetector](https://github.com/XiaoTong6666/KeyDetector) (23-check attestation validator). All keystore-level checks now pass.

- **Key deletion consistency**, After deleting a software-generated key, `getKeyEntry` now correctly returns `KEY_NOT_FOUND` instead of falling through to a stale live-patch fallback. Fixes binder consistency checks that detect ghost key responses.
- **generateKey timing normalization**, Software key generation RTT now matches real TEE latency profile (Gaussian distribution, mean=55ms, floor=15ms). Previously completed in ~4ms, which is an immediate timing side-channel.
- **Delete cleanup scope**, `deleteKey` now clears all cached state (patched chains, attestation keys) regardless of whether the key was software or hardware-generated.

---

## TEESimulator v4.4: AOSP Conformance

- **Binder error reply format**, Aligned EX_SERVICE_SPECIFIC wire layout with AOSP Status.cpp, including the remote stack trace header field.
- **Key enumeration**, Corrected list_past_alias pagination order to match AOSP database.rs semantics.
- **KeyMetadata fields**, Generated key responses now include modificationTimeMs, Tag.ORIGIN, and normalized KeyDescriptor fields per AOSP Keystore2.
- **Parcel handling**, hasException() preserves reply position for downstream consumers.

---

## TEESimulator v4.3: Performance & Reliability

- **Debug log gating**, `SystemLogger.debug()` now skipped entirely in release builds, eliminating unnecessary logcat syscalls on every intercepted transaction.
- **Supervisor backoff**, Exponential restart delay (500ms → 30s cap) prevents CPU spin if the daemon crashes repeatedly. Resets automatically once stable.
- **Process priority**, Daemon runs at nice=10, yielding CPU to foreground apps on constrained devices.
- **Map eviction**, Rate limiter and file lock maps now evict stale entries instead of growing unbounded.
- **CI pipeline**, Single-trigger build→release pipeline with proper changelog extraction and correctly sized artifacts.

---

## TEESimulator v4.2: Detection Evasion Hardening

Fixes 6 detection vectors flagged by attestation validator apps.

### Attestation Policy Enforcement

Replicate AOSP keystore2's `add_required_parameters()` validation that our software keygen path was bypassing:

- **CREATION_DATETIME**, Reject caller-provided input with `INVALID_ARGUMENT (20)`, matching `security_level.rs:424`. Our cert gen still adds its own timestamp, same as real keystore2.
- **Device ID attestation**, Reject ATTESTATION_ID_SERIAL, IMEI, MEID, SECOND_IMEI, and DEVICE_UNIQUE_ATTESTATION with `CANNOT_ATTEST_IDS (-66)`. No consumer app has READ_PRIVILEGED_PHONE_STATE.
- **Error reply format**, Fixed AIDL ServiceSpecificException parcel write order (was errorCode→message, now message→errorCode).

### Certificate Fix

Leaf certificate Subject CN corrected from "Android KeyStore Key" to "Android Keystore Key" (lowercase s), matching AOSP `KeyGenParameterSpec.java:282`. Both Kotlin and Rust paths.

### Binder Timing

Skip interception for system transaction codes (PING, INTERFACE, DUMP) above LAST_CALL_TRANSACTION. Eliminates the JNI round-trip that inflated binder ping ratio to 3.85x (detector threshold: 3.0x).

---

## TEESimulator v4.1: Boot Identity Persistence

Bugfix release. The vbmeta boot key digest was randomizing on every reboot, producing a different RootOfTrust in attestation certificates each boot.

On devices where the kernel doesn't set `ro.boot.vbmeta.public_key_digest`, the fallback chain hit random generation every boot because `resetprop` overrides for `ro.boot.*` props don't survive reboots. Added file-based persistence (`boot_hash.bin`, `boot_key.bin`) between the TEE cache and random fallback. Once determined, boot identity values persist across reboots.

Verified on Redmi 14C: second boot reads from persistent file instead of regenerating.

---

## TEESimulator v4.0: Native Rust Cert Generation

Major release. Certificate chain generation rebuilt from the ground up in Rust, replacing the BouncyCastle Java path for EC and RSA keys. Hardened against every known detector app.

### Native Cert Generation

The headline feature. `libcertgen.so` generates X.509 certificate chains using `ring` (EC-P256/P384) and `rsa` (RSA-2048/4096) with manual DER assembly. No more BouncyCastle quirks, issuer/subject DN bytes are injected directly from the keybox, ensuring byte-perfect chain linkage. BouncyCastle remains as fallback for unsupported curves (P-224, P-521, Curve25519).

### Anti-Detection Hardening

- **Challenge validation**, Oversized attestation challenges (>128 bytes) now return `INVALID_INPUT_LENGTH (-21)`, matching real KeyMint behavior. Previously accepted silently, DuckDetector exploited this.
- **Per-UID rate limiter**, 2 hardware keygens per 30s burst, 2 concurrent max. Overflow falls back to software certs. Blocks DuckDetector-style keygen flooding that starves GMS.
- **importKey eviction guard**, Retained patch chains prevent generate-then-import attacks that evict cached attestation data.
- **256KB native payload cap**, Oversized binder payloads bypass interception cleanly instead of stalling threads.
- **Alias size rejection**, Oversized key aliases rejected before they hit the binder buffer.

### Key Persistence

Generated keys now survive reboots. File-backed storage with file-level locking, preserved across keybox rotations. Banking and biometric apps that cache attestation keys no longer break after restart.

### Attestation Fixes

- Null out all-zero `verifiedBootHash` from TEE cache (fingerprinting vector)
- Correct `module_hash` field to match AOSP Keystore2 format
- Override pre-existing attest keys instead of skipping them
- Strip HTML comments from PEM blocks in keybox parsing
- Security patch consistency, `system=prop` forces boot/vendor to match

### Module Lifecycle

- Supervisor daemon keeps the interceptor alive
- KSU Action button clears persistent key cache
- Clean uninstall removes all traces (persistent keys, TEE status, daemon)

### Stability

- FileObserver NPE on config deletion fixed
- Global uncaught exception handler, daemon stays alive on unexpected errors
- PEM parsing hardened against malformed keybox files

### Tested Against

DuckDetector, Luna, Play Integrity, Key Attestation Demo, all passing on Redmi 14C (Android 14, Beanpod KeyMaster, KSU).
