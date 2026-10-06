# Native snapshot content inspection

`hol-guard-runtime policy-snapshot-inspect --stdin` reads one bounded, typed v3
snapshot and emits `guard-native-policy-content-inspection.v1` metadata. This
offline operation supports a publisher/cache bridge without reimplementing
business selector or budget validation outside Rust.

The result contains only version, canonical snapshot digest, recomputed
configuration and policy digests, business-binding presence, and fixed
`authenticity: not_checked` / `currentness: not_checked` states. It does not
return policy rules, account identifiers, signing keys or a MAC. Unknown fields,
explicit null business bindings, malformed typed content and oversized input
are refused with a finite error that does not echo input.

Inspection shares the content checks used by authenticated native admission.
It checks the snapshot's own declared context and expiry interval; it has no
trusted clock, generation floor, resident identity, scope owner or verifier
key. An expired or forged-MAC snapshot can therefore produce a diagnostic
result. A wrong claimed digest produces the independently recomputed digest,
so a bridge can compare it without recreating business digest semantics.

A bridge must separately check the claimed digests against the recomputed
values and verify the MAC with its trusted key before treating cached bytes as
authentic. Resident admission still uses `validate_v3` with trusted identity,
generation, clock and key context; inspection never replaces that function.
Content inspection cannot grant review, worker admission or provider dispatch.
It does not install policy, read state or contact a provider.

The existing Python publisher/cache does not yet use this operation. Cloud
business publication remains refused pending compatible delivery and parity;
credential isolation and live business journey qualification remain separate.
