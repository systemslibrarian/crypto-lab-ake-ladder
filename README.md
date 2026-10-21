# AKE Ladder

## What It Is

Implements Boneh–Shoup v0.6 AKE1 over ristretto255, Ed25519, HKDF-SHA-256 and AES-GCM; each of six insecure variations has a scripted attack over real wire operations. Additional acts compute AKE2eg, AKE4eg and AKE5 key agreements and show forward-secrecy, identity-protection and honest-Q deniability intuitions. Not production crypto — a teaching demo. All material is generated in memory; this static site has no account, backend or key storage.

## Exhibits

1. Step the honest AKE1 certificate, signature, CCA encryption, identity check and channel binding.
2. Remove one of six protocol protections; compare both parties’ actual session-key fingerprints and partner identities, then restore the field and see the same attacker procedure rejected.
3. Record AKE1 and AKE2eg AES-GCM messages and leak a long-term key; contrast with a leak of ephemeral α.
4. Compare AKE2eg’s clear certificates with AKE4eg’s encrypted certificates; try a fake responder.
5. Check genuine and Q-fabricated AKE5 transcripts with the same group-key consistency equations.

## When to Use It

Use this to study the exact mechanism and its failure boundary. Do not use the toy implementation, keys or protocols in a deployed security system.

## Live Demo

[Open AKE Ladder](https://systemslibrarian.github.io/crypto-lab-ake-ladder/) to drive the exhibits. The build uses Vite's `/crypto-lab-ake-ladder/` base for GitHub Pages.

## What Can Go Wrong

AKE1 authenticates its session but does not provide forward secrecy: a later leak of P’s decryption scalar reveals a recorded session key and the recorded application message. Omitting individual fields can instead expose the key, replay it, or cause identity misbinding.

## Real-World Usage

The CA and certificate encoding are a small teaching model. V6 uses an E_EG KEM with an AES-CTR DEM instead of the book’s trapdoor-function construction; the malleability is the taught point. AKE5’s demonstration is honest-Q intuition, not the formal simulator argument.

## How to Run Locally

```sh
npm ci
npm run dev
```

## Related Demos

[Protocol Checker](https://github.com/systemslibrarian/crypto-lab-protocol-checker) · [DH MITM](https://github.com/systemslibrarian/crypto-lab-diffie-hellman-mitm) · [TLS Handshake](https://github.com/systemslibrarian/crypto-lab-tls-handshake) · [Noise Pipe](https://github.com/systemslibrarian/crypto-lab-noise-pipe) · [Protocol Compose](https://github.com/systemslibrarian/crypto-lab-protocol-compose)

## Build & Verify

```sh
npm test
npm run build
npx playwright install chromium
npm run test:a11y
npm run test:mutations
```

73 executed unit cases cover the six live variations and their restored failures, honest binding, primitive known answers, and AKE2eg/AKE4eg/AKE5 exchanges. No published AKE1–AKE5 end-to-end test vectors exist. The replayable mutation harness contains 17 concrete source patches (13 verdict paths and the original four definition regressions). Each run first passes its named baseline test, requires a non-empty diff, a successful build and changed JavaScript bundle hash, then requires the owning test to fail and restores the original hash. The Playwright suite contains 15 claims tests and two accessibility state drives (1280px and 320px). It scans reachable desktop and mobile states for WCAG 2.1 A/AA issues and independently rederives displayed claims. GitHub Actions runs unit tests, production build and browser gate before deploying; it also gates Dependabot pull requests, groups minor/patch npm updates and dispatches a deploy after an automated merge.

## Performance

All runs are local to the browser. Work figures shown in the page are either actual counted operations or explicitly labelled mathematical estimates/extrapolations. Workers keep long searches cancellable where used. No speed number is a claim about a production deployment.

## Sources

- [Boneh–Shoup v0.6 chapter 21 and §12.4](https://toc.cryptobook.us/)
- [RFC 9496 ristretto255](https://www.rfc-editor.org/rfc/rfc9496)
- [RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869)

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Deviations from the brief

- The mutation runner uses structured Playwright reports, rejects timeouts, browser/setup failures and retries, requires the exact owning assertion, and reruns the restored test. Retaining the former text-search runner would incorrectly count infrastructure failures as kills. This intentional exception to the runner freeze matches Hash Hunt's hardened runner.
- The brief leaves its McGrew–Viega GCM case explicitly UNVERIFIED. The pinned multi-block substitute is NIST's [AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf), GCM-AES256 Example 2 (512-bit plaintext, no AAD, 128-bit tag). The actual AES-GCM wrapper is tested with the published IV through a test-only RNG mock.
- A finite set of leaked-signing-key decryption probes cannot prove forward secrecy. The page says exactly what was tried; DH security and erasure supply the cryptographic argument (Boneh–Shoup §21.3). The adversary receives the actual disclosed key and public recording. A negative-control unit test deliberately encrypts under that key and confirms the probe catches the exposure.

## Audit repair evidence

Protocol runs are coordinated in `src/ake/`; individual `src/attack/` modules receive public wire copies, corrupt-user signing capability or an explicitly leaked key. They cannot import honest state. Honest P creates the V1 application record; honest Q supplies V3's partner and binding. The ephemeral-alpha experiment replays a signed u to a fresh honest Q, derives the adversary's key, sends an application record, and checks Q's actual acceptance. The AKE4 forgery replays an authentic earlier signature on fresh DH values, with a successful verification of the original as its positive control.

Expandable educator inspectors include session keys and full bytes for verification; those inspector values are not inputs to the adversary. Browser tests independently encode tuples and use Node crypto for hashes, HKDF, AES-GCM and Ed25519; their AKE5 reference reimplements the equations over the public ristretto primitive. AKE1 post-leak decryption is independently recomputed from the disclosed scalar.

`src/kat/vectors.json` was extracted from primary texts, not recalled values: RFC 9496 A.1 (16) and A.2 (29); RFC 8032 §7.1 TEST 1, TEST 2, TEST 1024; RFC 5869 A.1/A.2; NIST SP 800-38A F.5.1's four blocks; NIST AES-GCM AES256 Example 2. The file records SHA-256 digests of the downloaded source files. URLs: [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.txt), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.txt), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.txt), [SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).

Counts: `npx vitest list --json` enumerates declarations in this Vitest version; `npm test` expands parameter rows to 73 cases. `npx playwright test --list` lists 17 browser tests. `scripts/mutations.json` has 17 entries. No tests are skipped.

Mutation restoration hashes the JavaScript files listed by each fresh Vite build manifest. Unreferenced files left by browser artifact collection are excluded; baseline, mutant and restored builds still have to satisfy every assertion and hash check.
