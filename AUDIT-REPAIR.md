# Audit repair verification

Audited baseline: `3ebac28c346d184c255127fd25f572da650608bf`. Repair scope: this repository only.

The supplied handoff and repair proposal were checked against the repository and its brief. The full numbered audit reports were not attached; descriptive labels are used where the supplied material did not establish a finding number. No unprovided finding is claimed resolved.

Dependencies were installed with `npm ci --offline --ignore-scripts` from the available cache. Local browser runs used `CHROMIUM_PATH=/tmp/chromium`; CI retains its normal Playwright browser installation. Builds include TypeScript checking. No tests were skipped.

## Findings and decisions

| Finding | Verified disposition and evidence |
| --- | --- |
| Missing primitive known answers | `src/kat/vectors.json` records primary source provenance; `primitives.test.ts` exercises all 16 RFC 9496 multiples, 29 invalid encodings, Ed25519 TEST 1/2/1024, HKDF A.1/A.2 and multi-block CTR/GCM. README explains the NIST substitute for the brief's unverified GCM case. |
| Adversary received honest state | Honest coordination moved to `src/ake/experiment.ts`; separate attack modules receive copied public wire values, corrupt-user signing capability or an explicitly disclosed secret. `boundaries.test.ts` checks imports and that public wire copies cannot alias honest state. |
| V1 circular application claim | Honest P seals a new application record with its accepted key; the adversary opens that record. Unit and browser checks establish its origin, independently decrypt it and check the unequal P/Q keys. |
| V3 manual partner assignment | The actual honest responder derives its partner and binding from the substituted certificate. Tests compare that view with independently encoded wire data. |
| Decorative PFS test | AKE2 disclosure passes the real signing key to three decryption probes. A deliberately signing-key-encrypted unit control is exposed, and a production-path mutant is killed by the browser oracle. AKE1's disclosed decryption scalar actually recovers the prior record. Finite probes do not prove forward secrecy. |
| Ephemeral leak and active probe | A leaked alpha drives a fresh session that honest Q accepts. The fake responder constructs ciphertext from public material and its own exponent; P validates the certificate and sends no c2. |
| Fabrication evidence | AKE4 reuses an authentic signature against fresh DH values and checks the original as a positive control. AKE5 uses public peer keys and Q's secret; the browser independently recomputes the key equations for both transcripts. |
| Rendered-vs-rendered claims | Full wire and educator key inspectors support independent tuple, binding, fingerprint, AES, HKDF and signature calculations in `e2e/reference.ts`. V2/V4/V6 replay records are independently decrypted; V6 also checks the actual changed CTR byte. |
| Missing verdict mutations | Thirteen verdict paths are covered, plus the four original definition mutations. Every entry must fail a named assertion, change a successfully built bundle, restore identical bytes and pass again. |
| Missing gate / modules / links | Schnorr-derived scan and contrast machinery now drives reachable AKE states at 1280px and 320px. Protocol, attack, record, binding and UI modules follow their responsibilities; missing related links are supplied. |

V6 is explicitly a replay, including a fresh initiator nonce and acceptance of an old application record under the reused key. Its display is derived from the variant's class; the browser independently expects replay for V2, V4 and V6.

## Executed validation

| Check | Observed result |
| --- | --- |
| `npm test` | 73 passed |
| `npm run build` | Passed |
| `npx playwright test` | 15 claims + 2 accessibility drives passed |
| `npm run test:mutations` | 17/17 killed and restored |

A mutation kill means a passing baseline, a non-empty source patch, a successful changed bundle, an assertion failure in the named owning test, an identical restored bundle and a passing restored test. Setup failures, crashes and test timeouts are rejected. Reproducible patches and test ownership are below. These local results do not claim a future hosted deployment or a formal security proof.

## Executable finding matrix

The descriptive finding IDs below identify concrete regressions; they do not invent the missing numbered audit report. Each row was observed failing only under its source patch. Other verified decisions and primitive checks are detailed above.

| Finding ID / regression | Verified | Fix (file:line) | Named test | Mutation name | Status |
| --- | --- | --- | --- | --- | --- |
| AK / V1 signs ciphertext again | Yes | `src/ake/variants.ts:4` | V1 attack has independently checked evidence | V1 signs ciphertext again | Fixed and verified |
| AK / V3 signs initiator identity | Yes | `src/ake/variants.ts:6` | V3 attack has independently checked evidence | V3 signs initiator identity | Fixed and verified |
| AK / V4 keeps encrypted identity | Yes | `src/ake/variants.ts:7` | V4 attack has independently checked evidence | V4 keeps encrypted identity | Fixed and verified |
| AK / V6 restores authenticated encryption | Yes | `src/ake/variants.ts:9` | V6 attack has independently checked evidence | V6 restores authenticated encryption | Fixed and verified |
| AK / V1 network edit no longer creates its claimed attack | Yes | `src/attack/v1.ts:7` | V1 attack has independently checked evidence | V1 network edit no longer creates its claimed attack | Fixed and verified |
| AK / V2 network edit no longer creates its claimed attack | Yes | `src/attack/v2.ts:2` | V2 attack has independently checked evidence | V2 network edit no longer creates its claimed attack | Fixed and verified |
| AK / V3 network edit no longer creates its claimed attack | Yes | `src/attack/v3.ts:4` | V3 attack has independently checked evidence | V3 network edit no longer creates its claimed attack | Fixed and verified |
| AK / V4 network edit no longer creates its claimed attack | Yes | `src/attack/v4.ts:3` | V4 attack has independently checked evidence | V4 network edit no longer creates its claimed attack | Fixed and verified |
| AK / V5 resigns with the honest certificate | Yes | `src/attack/v5.ts:3` | V5 attack has independently checked evidence | V5 resigns with the honest certificate | Fixed and verified |
| AK / V6 network edit no longer creates its claimed attack | Yes | `src/attack/v6.ts:6` | V6 attack has independently checked evidence | V6 network edit no longer creates its claimed attack | Fixed and verified |
| AK / honest binding loses initiator identity | Yes | `src/ake/binding.ts:4` | honest binding and fingerprints derive from complete wire bytes | honest binding loses initiator identity | Fixed and verified |
| AK / AKE1 leak takes the wrong key bytes | Yes | `src/ui/acts.ts:55` | AKE1 leaked scalar independently decrypts prior application record | AKE1 leak takes the wrong key bytes | Fixed and verified |
| AK / AKE2 accepts the leaked signing secret as its session key | Yes | `src/ake/ake2eg.ts:24` | AKE2 signing-key disclosure runs real rejected decryption probes | AKE2 accepts the leaked signing secret as its session key | Fixed and verified |
| AK / ephemeral leak uses the wrong exponent | Yes | `src/attack/ephemeral.ts:5` | ephemeral leak leads honest Q to accept a fresh adversary record | ephemeral leak uses the wrong exponent | Fixed and verified |
| AK / fake responder elicits P certificate before verification | Yes | `src/ake/ake4eg.ts:26` | active fake responder is rejected before c2 is sent | fake responder elicits P certificate before verification | Fixed and verified |
| AK / AKE4 forgery judge verifies old transcript instead | Yes | `src/ake/fabrication.ts:7` | AKE4 fabrication rejects a valid signature replayed onto fresh DH values | AKE4 forgery judge verifies old transcript instead | Fixed and verified |
| AK / AKE5 fabricated confirmation is corrupted | Yes | `src/ake/ake5.ts:24` | AKE5 real and Q fabricated confirmations independently recompute | AKE5 fabricated confirmation is corrupted | Fixed and verified |

## Preserved scope

The brief files, deployment workflows, registered Playwright port, shared header and theme pin were not edited. Supporting catalog and reference repositories were read only. See README “Deviations from the brief” for source-backed corrections and the intentional mutation-runner hardening.

## Final command excerpts

```text

npm test
Test Files  3 passed (3)
Tests  73 passed (73)

npm run build
> tsc --noEmit && vite build
✓ built in 97ms

CHROMIUM_PATH=/tmp/chromium npx playwright test
17 passed (1.1m)

CHROMIUM_PATH=/tmp/chromium npm run test:mutations
17 / 17 mutations killed and restored
```

Mutation restoration uses each freshly generated Vite manifest to identify emitted scripts. It excludes unreferenced stale browser artifacts while retaining the successful-build, changed-bundle, exact owning-assertion and identical-restoration requirements.
