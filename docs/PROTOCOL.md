# EHLS protocol guide

## Purpose and scope

EHLS delivers manufacturing instructions as bounded encrypted segments. The aim is to reduce the amount of usable instruction data held at the receiving endpoint and tie delivery to an enrolled machine and a verified session. A deployed system couples delivery to execution feedback and disposal of each working segment.

This guide documents the implementation in this repository. It is a Python reference, not a complete language-independent standard or an independent security audit. Models for enrollment, challenges, recovery, adaptive control and certificates are present; their application services are outside this extraction.

## Participants and lifecycle

The **server** owns the instruction source, segmentation, enrollment records and delivery policy. The **gateway** authenticates the machine and session, decrypts one working segment, submits commands and monitors execution. The **manufacturing machine** executes commands and emits feedback.

The intended state progression is `pending` → `authenticated` → `streaming` → `completed`, with `paused`, `terminated` and `error` alternatives. `SessionState` names these values; it does not enforce transitions.

A complete application must implement enrollment, active challenge verification, handshake authentication, expected-index tracking, buffer lifetime management, telemetry verification, halt behaviour, and reconnect policy. Defining a packet type does not implement that action.

## Machine identity

`MachineIdentityProfile` contains `cpu_id`, `firmware_version`, optional `board_serial`, four numeric feature groups, and a collection timestamp.

`canonical_mip_bytes()` selects **only** `cpu_id`, `firmware_version`, and `board_serial`, then serializes them using Python `json.dumps(..., sort_keys=True)` and UTF-8. Default JSON spacing and ASCII escaping are significant. `compute_mip_hash()` returns the lowercase SHA-256 hexadecimal digest of those bytes. The collection timestamp and numeric groups are excluded so telemetry drift does not change the identity hash.

`verify_mip_only()` has two tiers: exact comparison of `cpu_id` and `firmware_version` by default, and average relative divergence across enrolled numeric values with a default threshold of 0.15. Callers can supply a different exact-match field list, including `board_serial`. Hash inclusion and default comparison fields differ; integrators must choose their comparison policy explicitly.

`BehaviouralBaseline` represents the BIP: enrollment challenge ID, thermal ramp/overshoot/steady state, final XYZ position, motion duration and capture time. `compute_bip_hash()` hashes supplied bytes. Existing call sites use `baseline.model_dump_json().encode('utf-8')`; both endpoints need the same stored baseline serialization, including metadata. Hashing a newly sampled challenge result is not a substitute for hashing the enrolled baseline.

Passive identity matching is not proof of exclusive possession of hardware. Active challenge generation, measurement and tolerance verification require deployment code outside this repository.

## Session keys

### Identity-derived mode

`derive_session_key(mip_hash, bip_hash, nonce, timestamp)` computes:

```text
IKM  = UTF8(mip_hash) || UTF8(bip_hash) || nonce || UTF8(str(timestamp))
salt = nonce
info = b"EHLS-session-v1"
key  = HKDF-SHA256(IKM, salt, info, length=32)
```

The hashes are concatenated as hexadecimal text, not decoded digest bytes. The timestamp is Python's textual float representation, not a binary timestamp. Implementations must agree on the exact bytes. Use a fresh random nonce; the example requests 32 bytes.

The BIP argument must be nonempty. The helper does not validate every input as a well-formed digest or enforce nonce length, freshness, or timestamp policy. Applications must add those checks.

This mode has no independent secret if all derivation inputs are available to an observer, and it has no forward secrecy. HKDF cannot turn public fingerprints into a secret.

### X25519 mode

Each endpoint generates a fresh ephemeral keypair with `generate_ephemeral_keypair()`, exchanges the 32-byte public keys through an authenticated channel and computes:

```text
shared_secret = X25519(own_private_key, peer_public_key)
IKM = shared_secret || UTF8(mip_hash) || UTF8(bip_hash)
key = HKDF-SHA256(IKM, salt=nonce, info=b"EHLS-session-v1", length=32)
```

`derive_session_key_ecdh()` validates peer-key type and length and requires a nonempty BIP hash. This mode does not include the timestamp. Authenticate the key exchange and bind it to the authorized session. Forward secrecy depends on ephemeral-key handling and disposal; deleting Python references does not prove secure erasure.

The local example holds both endpoints in one process and assumes its synthetic identity and public-key exchange are trusted. It is not a network handshake implementation.

## Packet envelope

`ProtocolPacket` has the following fields:

| Field | Representation |
| --- | --- |
| `packet_type` | String from `PacketType` |
| `session_id` | String or null |
| `machine_id` | String or null |
| `timestamp` | Number; defaults to the local current time |
| `payload` | JSON object |
| `signature` | HMAC hex string or null |

Packet families include enrollment, handshake, diagnostic challenge/result/verification, segment delivery/ACK, telemetry, adaptive adjustment, halt, session end/ACK, heartbeat, reconnect, errors and job start. See `PacketType` for exact string values.

`serialize_packet()` emits Pydantic JSON as UTF-8 bytes. `deserialize_packet()` validates the model, **without authenticating it**. Payloads remain generic dictionaries; applications validate the required structure for each message type.

`sign_packet()` dumps the model in JSON mode excluding `signature`, then calculates HMAC-SHA256 over:

```python
json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

`verify_packet()` reconstructs that form and compares the hex tag in constant time. The signature covers all other envelope fields, including the payload. Implementations must reproduce Python JSON escaping and number representations. Cross-language canonicalization needs interoperability vectors before production use.

Neither timestamps nor valid signatures enforce freshness automatically. Track the active session, authorized machine, expected index and accepted message transitions. Enforce size limits before JSON parsing and validate payload sizes before buffer allocation.

## Encrypted segments

`EncryptedSegment` contains `segment_index`, `layer_start`, `layer_end`, `ciphertext`, `iv`, `checksum` and `total_segments`.

`encrypt_segment()` requires a 32-byte key, chooses a random 12-byte IV and returns AES-GCM ciphertext with its appended authentication tag, the IV, and a hexadecimal HMAC-SHA256 checksum. AES-GCM's tag is 16 bytes in this implementation.

For streaming, supply the following AAD to both encryption and decryption:

```text
b"EHLS-v1|" || UTF8(session_id) || b"|" || UTF8(str(segment_index))
```

Construct AAD from the receiver's authorized session and expected index. Avoid ambiguous session identifiers containing `|`; the helper itself does not validate them. The outer segment checksum covers `iv || ciphertext || aad`. `decrypt_segment()` checks it before AES-GCM decryption. The API permits omitted AAD for compatibility, but the streaming example always supplies it.

Layer bounds and total count are not part of segment AAD. Include the segment inside a signed packet to authenticate these metadata fields as well. The example encodes the serialized segment as the object at `payload.segment`; this is an example convention, not a separately validated payload schema.

`serialize_segment()` emits JSON with standard base64 strings for `ciphertext` and `iv`. `deserialize_segment()` reverses this. There is no binary version header in these JSON helpers; `WIRE_VERSION = 0x01` exists as a constant and is not automatically emitted by `serialize_segment()`.

AAD makes altered session/index values fail integrity checks. Replaying an identical segment with its original AAD still decrypts; application state must reject already-consumed indices. Treat duplicate, missing, or out-of-order delivery as explicit state events.

## Execution, memory and acknowledgements

A deployment should lock a bounded working buffer, validate/decrypt the segment, submit instructions, correlate execution feedback, wipe the buffer and only then acknowledge it. An HTTP command response alone may show acceptance without proving physical completion.

`SecureBuffer` uses a selected OS memory backend and raises `SecureBufferLockError` when locking fails in the default strict mode. Context-manager exit calls `release()`, which overwrites the managed allocation, unlocks it and marks it released. Overwriting uses random passes followed by zeroing. OS locking availability depends on platform and resource limits.

`gateway/memory_lock_backends.py` supplies POSIX `mlock` and Windows `VirtualLock`. SGX, TrustZone and SEV-SNP classes raise `NotImplementedError`. `gateway/secure_zero.py` selects a platform zeroing primitive or a ctypes fallback.

Python decryption returns immutable `bytes` before data enters a managed buffer; reads produce additional byte copies. Managed-buffer wiping does not erase every such copy, ephemeral private key, session key, library allocation, network buffer, or printer queue. Locking alone does not prevent privileged memory reads or establish trusted execution. The code cannot guarantee that a complete program is unrecoverable from all process memory or persistent storage.

The local example checks synthetic bytes instead of driving hardware. It wipes the managed buffer before constructing a signed simulated ACK and rejects duplicate/out-of-order segment indices. Its receiver is single-session and synchronous; production failure handling must terminate or explicitly reconcile state after uncertain execution. Blindly resending a motion or extrusion command can repeat the physical action.

## Recovery and termination

The models provide reconnect and termination message types. This library does not implement durable checkpoints or automatic recovery. A deployed protocol should reauthenticate identity, establish fresh keys, reconcile the last physically confirmed segment, and reject traffic from obsolete sessions. Dropping references in this demonstration is resource cleanup, not evidence of universal secret destruction.

## Verification

Run `python -m pytest -q` after installing `.[dev]`. Tests cover encryption and integrity failures, changed AAD, packet round trips/signatures, X25519 agreement, memory wiping, strict lock failure, OS backend selection, and the example receiver's replay/order/authentication checks. Tests of memory lock wrappers do not imply that every deployment has permission to lock memory.

No test in this extraction proves physical printer completion or whole-system non-persistence. Those require deployment-specific hardware and operating-system evidence.
