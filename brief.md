# Build brief — `crypto-lab-ake-ladder`

**2026-10-20. Brief only; no repository exists yet.** Written against
`audits/_MASTER-TEMPLATE.md` (catalog `20cb434d89e4`) — §0 through §6 apply unchanged.
Source of the gap: Boneh–Shoup v0.6, Chapter 21 — §21.2 (protocol AKE1, Fig. 21.1, and AKE1eg,
Fig. 21.2), §21.2.1 "Insecure variations" (Variations 1–6), §21.2.2 Summary, §21.3 (AKE2 /
AKE2eg, Figs. 21.3–21.4), §21.5 identity protection (AKE4 / AKE4eg, Figs. 21.7–21.8), §21.7
deniability (AKE5, Fig. 21.10), §21.8 channel bindings.

**Verdict: new repository.**

```
NEW DEMO BRIEF
- Repo name:         crypto-lab-ake-ladder
- Short name (H1):   AKE Ladder
- Subtitle:          Authenticated key exchange · Boneh–Shoup ch. 21
- One-liner:         Build a signed, encryption-based key exchange over ristretto255 and Ed25519, then remove one field at a time and run the attack each removal enables.
- Concept to teach:  Every field in a secure AKE is there because removing it enables a specific, nameable attack: key exposure, replay, or identity misbinding.
- Primitives/spec:   ristretto255 (RFC 9496), Ed25519 (RFC 8032), HKDF-SHA-256 (RFC 5869), AES-256-GCM and AES-CTR (WebCrypto); protocols AKE1, AKE2eg, AKE4eg, AKE5 exactly as in Boneh–Shoup v0.6 ch. 21
- Accent (--accent): [central assignment]
- Favicon emoji:     [central assignment]
- In scope:          AKE1 with hashed-ElGamal CCA encryption (B–S §12.4) and a toy CA; Variations 1–6 of §21.2.1, each with a scripted adversary that succeeds against the real implementation; channel bindings (§21.8) compared on both sides; PFS contrast AKE1 vs AKE2eg (§21.3) with an after-the-fact long-term-key leak; ephemeral-key leak in AKE2eg; identity protection AKE2eg vs AKE4eg (§21.5) for a passive observer and an active fake responder; deniability contrast AKE4eg vs AKE5 (§21.7) as "could Q have produced this transcript alone?"
- Non-goals:         Formal security definitions and proofs (§21.9); HSM security and AKE3 (§21.4); one-sided AKE (§21.6); AKE6; PAKE (§21.11); online-TTP protocols (§21.12); TLS itself (§21.10); STS (Exercise 21.1); real networking; persistence of any key
- Category:          [central assignment] (suggest KEY EXCHANGE + PROTOCOLS + ATTACKS)
- Level (suggested): Advanced (Act 1 readable at Intermediate)
- Section (suggested): key-exchange (alternative: cryptanalysis, "protocol composition flaws")
```

## Overlap check — what I read, and what I found

Grep across `/home/claude/labs/*` (node_modules, .git, dist excluded) for
`misbind|unknown.?key.?share|UKS`, `key.?compromise imperson|KCI`, `identity (protection|hiding)`,
`deniab`, `channel binding`, `station.?to.?station|STS`, and case-sensitive `SIGMA`. Every hit
inspected:

- **crypto-lab-protocol-checker** `adbe6c0612e5` — Dolev–Yao search. Its goal model is
  reachability of a secret term: `src/symbolic/protocol.ts:52` (`goal: Term; // "attacker
  learns this term"`) with an honest-peer guard at `:54–58`; `src/symbolic/search.ts:112–113`
  (`goalReached = guardOk(node) && canSynth(proto.goal, …)`). It can therefore find attacks in
  which the adversary *learns* a secret (e.g. Variation 1's chosen key k′). It cannot express
  Variation 2 or 4 (a replayed key the adversary never learns) or Variations 3 and 5 (P and Q
  share a key nobody else knows, but disagree about who they are talking to) — those violate
  authentication, not secrecy. Library at README §8: NSPK, NSL, naive DH, signed DH, toy
  Kerberos. Link to it; do not port it.
- **crypto-lab-diffie-hellman-mitm** `f5679cc9b202` — signed DH over WebCrypto ECDSA P-256.
  Misbinding appears only as a glossary entry (`src/ui.ts:783`) and a code comment
  (`src/engine.ts:278`); the banner at `src/ui.ts:731` names SIGMA's MAC as "more machinery"
  it does not implement. No misbinding attack is executed.
- **crypto-lab-tls-handshake** `3da1dab9287f` — MITM strategies (`src/handshake.ts:757–780`:
  reuse-cert, own-key, relay) against CertificateVerify. Transcript binding vs MITM, not the
  §21.2.1 ladder.
- **crypto-lab-noise-pipe** `689e2b07a366` — identity hiding as a per-pattern property table
  (`src/patterns.ts:36–41`, `src/ui.ts:504`) and the handshake hash as channel binding
  (`src/patterns.ts:547,566`). A property listing, not an executed observer/probe contrast.
- **crypto-lab-hpke-envelope** `bb39ab7a5f04` — KCI as prose naming RFC 9180 §9.1.1
  (`src/ui/modes.ts:39,46`, `src/ui/statics.ts:136`).
- **crypto-lab-ssh-handshake** `b7e334bc33fa`, **crypto-lab-x3dh-wire** `bf9022613788`,
  **crypto-lab-kerberos** `2d00aed8365d` (Lowe attack/fix, `src/app.ts:6–27`),
  **crypto-lab-pqxdh-wire** `d057c986bbb3` (deniability named only as an extension seam in its
  `brief.md:120`) — none executes a §21.2.1 variation, a PFS leak contrast of AKE1 vs AKE2, or
  a deniability fabrication.
- **crypto-lab-protocol-compose** `f5c0b60c2614` — one sentence on sign-then-encrypt
  (`src/main.ts:384–385`); its in-flight Katz–Lindell extension builds signcryption identity
  binding. Different problem: signcryption binds identities into a *single message* sent once;
  this lab is about a two-party *session* agreeing on a key and a partner. Cross-link both ways.

No `STS`/station-to-station hit anywhere. Before building, re-run the grep above against
current clones and report any new hit.

## The seven §1 sections

### SCOPE

Plain-language intro (before any hex): "Two computers want a shared secret key and want to be
sure who is on the other end. A protocol that gets the key right but the names wrong is broken
— and so is one that gets the names right but lets an old key come back. This lab builds one
correct protocol and then lets you take it apart."

1. **Act 1 — AKE1, built for real (§21.2, Fig. 21.1).** P sends `(r, Cert_P)`; Q replies
   `(c = Enc_P(k, id_Q), σ = Sig_Q(r, c, id_P), Cert_Q)`. Step-through with each field
   highlighted as it is created, verified, and consumed. Both parties' result cards show
   *session-key fingerprint* and *partner identity*, plus the §21.8 channel binding
   `(id_P, id_Q, r, c)` each side computes. A one-line note gives the book's
   "implicit authentication" caveat for Q (§21.2, final paragraph).
2. **Act 2 — the ladder (§21.2.1).** Six toggles, in the book's order and with the book's
   names. Selecting one shows the modified message flow, then **Run the attack** executes a
   scripted adversary against the real implementation:
   - V1 *do not sign c — a key exposure attack*: adversary re-encrypts its own k′ to P; P
     holds k′, Q holds k. Consequence: the adversary decrypts P's first AES-GCM record (the
     book's bank-request example).
   - V2 *do not sign r — a replay attack*: recorded `(c, σ, Cert_Q)` replayed to a later P
     instance; P reuses the old k. Consequence: a recorded "transfer" record is accepted again.
   - V3 *do not sign id_P — an identity misbinding attack*: the adversary registers R at the
     CA with P's public key (the CA does not require proof of possession — §21.2 "Certificate
     authority"), substitutes `Cert_R`; P thinks it talks to Q, Q thinks it talks to R; the key
     is shared and unknown to the adversary (the book's voucher-card example).
   - V4 *do not encrypt id_Q — a replay attack*: corrupt-but-registered R re-signs a recorded
     c with its own key; second P instance holds the old k and thinks it talks to R.
   - V5 *encrypt r instead of id_Q — an identity misbinding attack*: corrupt R re-signs Q's c;
     P thinks it talks to R, Q thinks it talks to P; no key hijack needed.
   - V6 *the need for CCA-secure encryption*: swap the AEAD DEM for AES-CTR; the adversary
     XORs `id_Q ⊕ id_R` into the identity field of a recorded c without knowing k and runs the
     V4-style replay against the **full** AKE1 signature. (The book instantiates V6 with a
     trapdoor-function scheme over a stream cipher; this lab uses the same E_EG KEM with a
     stream-cipher DEM. The malleability being exploited is identical; say so on the page.)
     The Bleichenbacher route the book also names is prose plus a link to RSA Forge.
   For each, an outcome table: P's view, Q's view, adversary's knowledge, attack class
   (key exposure / replay / identity misbinding — the three classes of §21.2.2), and the two
   channel bindings side by side. **Restore the field** re-runs the identical adversary and
   shows it fail at the named check.
3. **Act 3 — forward secrecy (§21.3).** Record one AKE1 session and one AKE2eg session (with an
   encrypted AES-GCM message in each). Then **Leak P's long-term key**: for AKE1 this is the
   decryption key, and the adversary decrypts the recorded c, recovers k, and reads the
   recorded message; for AKE2eg it is the signing key, and the recorded session stays sealed.
   Second button, **Leak an ephemeral α** (§21.3 "Erasing ephemeral data"): with α and P's
   signature on u, the adversary completes new sessions as P with any Q.
4. **Act 4 — identity protection (§21.5).** Passive-observer view of AKE2eg vs AKE4eg wire
   bytes: certificates in the clear vs only `u`, `v` and AEAD ciphertexts. Active probe: a fake
   responder answers P's AKE4eg `u`; P decrypts `c1`, fails to validate the fake `Cert_Q`, and
   aborts **before** sending `c2`, so the probe learns nothing about P. Also show the book's
   asymmetry: an active initiator does learn Q's identity.
5. **Act 5 — deniability (§21.7).** "Could Q have produced this transcript alone?" For AKE4eg,
   Q tries to fabricate a session with P without P: it cannot produce a valid
   `Sig_P(2, u, v)`, and the judge's verifier rejects. For AKE5, Q picks µ itself and computes
   `(g^α g^µ)^(β+ν)` and `(g^µ)^ν` from P's public key and its own β, ν, producing a transcript
   and session key of exactly the same form. The judge, handed everything Q holds (transcript,
   key, β), runs the same consistency checks on the real and the fabricated session and both
   pass — so neither proves P took part. Honesty box: this shows the honest-Q
   intuition only; the book's argument for P's deniability uses a simulator that observes Q's
   random-oracle queries and recognises DH triples (pairing), and §21.7 ends "On the limits of
   deniability".

Non-goal notes (one line each, in-page): formal model §21.9; HSM security and AKE3 §21.4
(extension seam); one-sided AKE §21.6; AKE6 §21.7.2; PAKE → PAKE Gate / OPAQUE Gate / SPAKE
Gate; online TTP §21.12 → Kerberos v5; TLS §21.10 → TLS Handshake; STS → extension seam.

### SECURITY / CORRECTNESS INVARIANTS

1. Every primitive is real: ristretto255 and Ed25519 via `@noble/curves` (the version line the
   fleet already uses — grep sibling `package.json` files and match it), HKDF/AES-GCM/AES-CTR
   via WebCrypto. No simulated group arithmetic, signature, or ciphertext.
2. Every signed or hashed tuple uses one canonical encoding: a domain tag naming protocol and
   variant (e.g. `"AKE1/V0/sig"`) followed by length-prefixed fields. No bare concatenation.
3. AKE1's encryption is B–S §12.4's E_EG: `v = g^β`, `w = u^β`, `key = HKDF(v ‖ w)`,
   DEM = AES-256-GCM (one-time AE). V6's DEM is AES-CTR with no tag and lives in its own module,
   is never the default, and is visibly marked broken.
4. Group elements are decoded with ristretto255's canonical decoding, which rejects
   non-canonical encodings (B–S Remark 12.1: P must check v ∈ G). A decode failure aborts the
   run with the field named.
5. Each variation is a separate protocol definition, selected only by the ladder toggle; the
   honest AKE1 code path has no branches for variations. The default state is the honest
   protocol.
6. The adversary is scripted but has no back door: it only uses wire messages, public keys,
   CA registration, and keys of corrupt users it registered. A test asserts the adversary
   module never imports honest-party secret state.
7. A verdict reports what the parties actually computed: session keys are compared by
   recomputed fingerprint, partner identities as returned by the protocol run.
8. All key material is per-session in memory; nothing persisted.

### ARCHITECTURE

```
src/group/ristretto.ts     scalar/point helpers over @noble/curves ristretto255
src/pke/eeg.ts             B–S §12.4 E_EG with AES-256-GCM DEM (CCA, ROM)
src/pke/eeg-ctr.ts         same KEM, AES-CTR DEM — BROKEN, V6 only
src/sig/ed25519.ts         thin wrapper; canonical-encoding signer
src/ca/ca.ts               toy CA: register(id, pk, {requirePoP:false}) → Cert
src/encode.ts              domain-tagged length-prefixed tuple encoding
src/ake/ake1.ts            honest AKE1 (Fig. 21.1)
src/ake/variants.ts        V1–V6 protocol definitions (one exported object each)
src/ake/ake2eg.ts          Fig. 21.4
src/ake/ake4eg.ts          Fig. 21.8 (k, k1, k2 := H(g^α, g^β, g^αβ))
src/ake/ake5.ts            Fig. 21.10
src/ake/binding.ts         §21.8 channel bindings per protocol
src/attack/<v1..v6>.ts     scripted adversaries; attack/pfs.ts; attack/probe.ts; attack/fabricate.ts
src/record/aead.ts         AES-GCM application records keyed from the session key
src/ui/*                   acts, outcome tables, wire view
```

### UI

The central metaphor is a ladder of fields. Act 2's core interaction:
1. Pick a rung (V1–V6); the protocol diagram redraws with the removed field struck through.
2. **Run honest** — both parties finish; outcome table green.
3. **Run the attack** — the adversary's moves animate one wire message at a time (motion tied
   to each message, never idle); the outcome table fills in.
4. **Restore the field** — identical adversary, attack fails at the named check (signature
   verify, decryption, identity check).
Below 640px the two-party diagram stacks into a single column with message order preserved.

### VISUAL SEMANTICS

Colour tracks the system's integrity, not whether a function returned true: a run where both
parties "succeed" but disagree about partners reads **ALARM — MISBOUND**; a run where P accepts
a key the adversary chose reads **ALARM — KEY EXPOSED**; replay reads **ALARM — REPLAYED KEY**.
Every state carries icon + text + colour. Channel bindings that differ while keys match are
shown as a split badge "SAME KEY — DIFFERENT BINDING".

### EDGE CASES

- Tampered `Cert_*` (CA signature fails) → abort, "certificate invalid".
- Non-canonical ristretto255 encoding of v → abort, "v ∉ G (decode rejected)".
- AEAD tag failure in E_EG → abort, "decryption failed" — never a partial plaintext.
- Decrypted identity ≠ certificate identity → abort, names both.
- Running an attack against the honest protocol → the adversary's script runs and fails at the
  first check it cannot pass; the page names that check.
- Re-selecting the same rung does not clear a fresh verdict; changing rung retires it and says so.

### EXTENSION SEAMS

- `// [extension] point` in `src/ake/` registry: AKE3 and an HSM signing-oracle model (§21.4).
- `// [extension] point` in `src/ca/ca.ts`: `requirePoP` — proof of possession at registration as
  an alternative defence against V3's key hijack.
- `// [extension] point` in `src/ake/`: STS (Exercise 21.1) and its misbinding variants.

## Tests

- **KATs (primitives):** RFC 9496 Appendix A.1 (multiples of the generator) and A.2 (invalid
  encodings must be rejected); RFC 8032 §7.1 Ed25519 TEST 1, TEST 2, and TEST 1024 (1023-byte
  message, well past one SHA-512 block); RFC 5869 Appendix A.1 and A.2 (A.2 has 80-byte
  IKM/salt/info and L = 82, more than one SHA-256 block); AES-CTR: NIST SP 800-38A F.5.1
  CTR-AES128.Encrypt (four blocks, per the Appendix F introduction); AES-GCM: a multi-block
  vector from McGrew–Viega's GCM specification test cases `[UNVERIFIED — confirm the test-case
  number and values against the primary PDF before pinning]`. There are no published test
  vectors for AKE1–AKE5; say so in the README.
- **Protocol tests (Vitest):** honest runs of AKE1/AKE2eg/AKE4eg/AKE5 agree on key, partner,
  and binding; each V1–V6 adversary succeeds on its variant and fails on honest AKE1 at the
  named check; PFS: the AKE1 leak recovers the recorded message, the AKE2eg leak does not.
- **claims.spec.ts (§4.1b):** independent re-derivations — recompute each party's channel
  binding from the wire bytes shown and compare to the rendered binding; recompute the session
  key fingerprint from the displayed key material; in V3/V5, assert P's displayed partner ≠
  Q's displayed partner while the displayed key fingerprints are equal; in V6, XOR the two
  displayed ciphertext identity fields and assert it equals `id_Q ⊕ id_R`; retirement and
  no-op guard per §4.1b.
- **§4.1c:** one mutation per rendered verdict (each of the six attack verdicts, the three PFS
  verdicts, the probe verdict, the two fabrication verdicts, and the honest verdict), run from
  a script with concrete patches as the template requires for a verdict-rendering lab.
- **§4.1d negative claim:** "AKE1 does not provide forward secrecy: a later leak of P's
  decryption key exposes earlier session keys." Evidence fixture: the Act 3 AKE1 session —
  every handshake check passed at the time (certificates, signature, decryption, identity) and
  the post-leak panel shows the recorded message decrypted. Verdict shape: `AUTHENTICATED —
  AND EXPOSED LATER`.

## Honesty notes for the page

- Not production crypto — a teaching demo. The CA, certificates and wire encoding are this
  lab's own; real CAs and X.509 are out of scope.
- Every attack runs against real primitives; the network and the adversary's scheduling are
  modelled in-page.
- The deniability act shows only that an honest Q could fabricate an AKE5 transcript; it does
  not reproduce the book's simulation argument.
- Variation 6 uses an E_EG + stream-cipher instantiation rather than the book's E_TDF one.

## Links out

Protocol Checker (machine-found attacks on secrecy goals), DH MITM (signed DH), TLS Handshake,
Noise Pipe (identity hiding per pattern), SSH Handshake, X3DH Wire, Kerberos v5, HPKE Envelope
(KCI), Protocol Compose (signcryption), RSA Forge (Bleichenbacher), PAKE Gate, OPAQUE Gate.

## Sources

- D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*, v0.6, Jan. 2023, ch. 21 and
  §12.4 — https://toc.cryptobook.us/
- H. Krawczyk, "SIGMA: The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use
  in the IKE Protocols," CRYPTO 2003, LNCS 2729, pp. 400–425 —
  https://www.iacr.org/archive/crypto2003/27290399/27290399.pdf (cite for the
  sign-then-MAC-under-the-derived-key lineage behind AKE4-style identity protection; the book's
  v0.6 notes do not yet carry citations).
- W. Diffie, P. C. van Oorschot, M. J. Wiener, "Authentication and Authenticated Key
  Exchanges," Designs, Codes and Cryptography 2(2):107–125, 1992, doi:10.1007/BF00124891 (STS;
  extension seam only).
- RFC 9496, The ristretto255 and decaf448 Groups (Dec. 2023) — https://www.rfc-editor.org/rfc/rfc9496
- RFC 8032, EdDSA, §7.1 — https://www.rfc-editor.org/rfc/rfc8032
- RFC 5869, HKDF, Appendix A — https://www.rfc-editor.org/rfc/rfc5869
- NIST SP 800-38A, Appendix F.5.1 —
  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
