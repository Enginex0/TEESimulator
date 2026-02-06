## TEESimulator v3.2: Anti-Detection Hardening & Key Persistence

This release hardens TEESimulator against active attestation probing by detector apps (DuckDetector, Luna, GarfieldHan) while introducing persistent key storage that survives daemon restarts and reboots.

### Anti-Detection Hardening

*   **Per-UID Hardware Keygen Rate Limiter**: Caps hardware key generation at 2 per 30-second window with 2 max concurrent requests per UID. Overflow requests fall back to software certificate generation, preventing binder thread starvation from flood attacks.
*   **importKey Eviction Defense**: Retains patched attestation chains when `importKey` overwrites an attested alias. Blocks the generate-then-import attack vector used by GarfieldHan and similar detectors.
*   **Native Binder Payload Cap**: Bypasses interception for payloads exceeding 256KB, preventing thread starvation from oversized binder transactions.
*   **Oversized Alias Rejection**: Rejects aliases that would exhaust the binder buffer, closing another flooding vector.

### Security Patch Consistency

*   **Three-Way Patch Level Alignment**: When `system=prop` in `security_patch.txt`, boot and vendor patch levels are forced to `prop` as well. All three ASN.1 attestation tags (706/718/719) now resolve via `SystemProperties.get()` to match what detector apps see through `getprop`.

### Key Persistence

*   **Generated Key Persistence Layer**: Keys from `generateKey` are persisted to disk in binary format with version headers and atomic writes (tmp + rename).
*   **Automatic Restoration**: Persisted keys are restored on daemon startup without re-attestation.
*   **Keybox Rotation Survival**: Generated keys survive keybox.xml changes — only PATCH-mode cert chains are invalidated.
*   **File-Level Locking**: Concurrent read/write access to persisted keys is serialized to prevent corruption.

### Process Reliability

*   **Fork-Based Supervisor Daemon**: Replaces the restart loop with a native fork-based supervisor for near-instant recovery.
*   **Attestation Leak Blocking**: Returns `DEAD_OBJECT` to callers when the interceptor service is unavailable, preventing unpatched attestation from leaking through.
*   **Global Exception Handler**: Catches uncaught exceptions and triggers clean daemon restart instead of silent death.
*   **FileObserver NPE Fix**: Prevents crash when config files are deleted while being observed.

### Upstream Cherry-Picks

*   **KeyUsage per HAL spec** (#119): Correct certificate KeyUsage based on KeyPurpose.
*   **Reference leak fix** (#122): Resolve strong reference leak and warnings in binder interception.

### Module Lifecycle

*   **`action.sh`**: Purge persistent key storage via KSU Manager Action button. Shows key count and storage size before clearing.
*   **`uninstall.sh`**: Clean module removal — kills daemon, removes generated data, preserves `target.txt`, `keybox.xml`, and `security_patch.txt`.

### PKI Fixes

*   Strip HTML comments from PEM blocks before parsing.

