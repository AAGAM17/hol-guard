# Native snapshot construction

`hol-guard-runtime policy-snapshot-build --stdin` constructs a canonical v3
snapshot from one bounded `guard-native-policy-build.v1` request. This is an
offline publisher operation, not a resident or MCP operation. It does not read
keys or configuration, install a policy, write state, approve a request or
dispatch a provider action.

The trusted publisher supplies version `1`, a 32-byte `verifier_key` array,
generation, runtime identity, rule digest, mode, scope contract, effective
policy, issue/expiry timestamps and optional command and business bindings.
The business binding uses the existing strict native contract; explicit null
is rejected while omission preserves the legacy shape. Unknown and duplicate
fields are rejected. Input is capped at the snapshot byte limit before JSON
decoding. Complete output is bounded before MAC construction.

Rust computes the effective configuration digest, policy digest, key identifier
and integrity MAC with the existing snapshot owners, then validates the result
before emitting canonical bytes. Business selectors and budget declarations
are preserved in that authenticated snapshot. The key is never a response
field. Owned input and key buffers are zeroized on return, including errors;
decode, validation and input failures return one finite error code without
reflecting request data. Supply publisher key material through private stdin,
never command arguments, logs or model-facing tools.

Construction does not authenticate the caller or establish installed authority.
The caller already owns the supplied signing key. Runtime/rule identities,
scope, timestamps and generation are publisher inputs; constructing bytes
does not prove they match the active resident. Existing resident admission must
independently enforce current identity, scope, generation floor and expiry.
This operation cannot mint worker admission or a provider credential.

The existing Python publisher does not yet call this operation or accept the
business field in its transport/cache lifecycle. Cloud publication remains
refused pending compatible authenticated delivery and parity. This constructor
does not qualify a managed worker, credential isolation, a live provider action
or a complete user journey.
