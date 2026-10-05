# Worker-owned account lifecycle

`GoogleSendAccount` retains a worker-verified send credential while preparing
separate immutable command inputs. Each input still requires the existing native
policy, exact review and single-use dispatch path. Preparing several inputs does
not approve them or authorize replay of a previous transaction.

The account owns refresh material. Per-input credentials contain only a private
zeroizing access-token copy, verified identity, original deadlines and a shared
revocation lease. No token getter, serializer, public credential clone, reload
constructor or standalone send method is added.

Revocation or dropping the account invalidates every pending input. This is
local admission revocation, not Google OAuth grant revocation. The fixed send
transport holds a read lease through its bounded HTTP call; revocation
waits for an admitted call and then refuses later calls. An admitted HTTP request
cannot be undone. Network/provider uncertainty still forbids automatic resend.

Replacing authorization requires a fresh worker-verified credential for the
same opaque account, tenant and exact verified primary mailbox. Wrong purpose,
expired authorization and changed identity leave the current account intact.
Successful replacement invalidates all old pending inputs; the caller must
prepare and review fresh inputs. A revoked owner cannot be revived by replacement.

Replacement currently consumes the existing verified OAuth completion result.
It does not implement a refresh-token exchange, persistent enrollment, an
authenticated worker registry, disconnect UI or isolated credential custody.
Those remain necessary for the real non-engineer setup/task journey. The
production native worker-admission type still has no valid value. Source tests
qualify lifecycle and transport admission only; no provider account, installed
runtime, live inference or protected business mode is qualified here.
