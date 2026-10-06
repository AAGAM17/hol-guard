# Native business snapshot publisher bridge

The internal snapshot builder, durable generation/cache flow and transport
accept an optional `business_policy` declaration. Omission keeps the legacy
path. This plumbing supplies no declaration source or activation authority:
the ordinary publisher still supplies none. Cloud publication remains refused.

For a business declaration the bridge requires a compatible selected native
runtime advertising both `native-policy-snapshot-build-v1` and
`native-policy-snapshot-inspect-v1`. An unavailable or older consumer refuses
with `native_business_policy_consumer_unavailable`; there is no Python business
validator, predicate, digest implementation or semantic fallback.

The constructor receives the publisher's existing normalized native policy,
scope, mode, generation, expiry and purpose-specific verifier key through
bounded stdin. Output must preserve those inputs and the captured business
declaration. The bridge independently checks key identity and the existing
canonical snapshot HMAC. Owned temporary key-list contents are cleared;
Python immutable serialization copies cannot promise memory erasure.

Cache validation uses the Rust content inspector and compares canonical
snapshot identity plus **both** recomputed config and policy digests. Inspector
authenticity and currentness must remain `not_checked`. Cache MAC verification
and actual resident admission remain separate: resident admission supplies the
trusted clock, runtime identity, rule digest and generation floor. Keyless
content success cannot authenticate a forged MAC or establish currentness.
Successful finite content projections are memoized in a bounded process-local
cache keyed by selected runtime identity and canonical snapshot digest. No
request content or verifier key is retained in that cache. A current compatible
consumer and remaining deadline are checked even on a cache hit; MAC and time
admission are never memoized. Build/inspect probes and processes consume the
caller's remaining publication budget. Declaration/capability validation
precedes business verifier-key provisioning; refusal does not install a key.

Semantic generation identity comes from a non-installed native constructor
value with synthetic key/generation/times, which do not participate in policy
identity. The actual snapshot is signed with the derived publisher key, stored
under the existing private lock/transaction flow and sent through the existing
acknowledgement/recovery protocol. A captured wire copy keeps declaration
mutation from changing the value between identity and materialization.

Regressions cover consumer refusal, legacy omission, binding preservation,
cache MAC verification, forged MAC, changed content and claimed digests,
malformed declarations, exact cache reuse, generation changes and renewal.
A real native transport regression uses one synthetic master, a disposable
Guard home, native command authority and a real resident acknowledgement. Its
resident is closed afterward; it invokes no provider operation.

This proves internal publication plumbing only. An authenticated declaration
producer, automatic publisher input fingerprint/reconnect integration,
negotiated Cloud publication parity, worker admission and provider/harness
journeys remain unqualified. Do not lift publication refusal or infer a
protected account from these tests.
