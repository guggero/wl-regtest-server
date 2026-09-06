# Implementation and validation

The operator uses the public Wavelength protocol at
[`f7cc57a0042e`](https://github.com/lightninglabs/wavelength/commit/f7cc57a0042ec2e2106035fe0f2f5e6590967f8a),
Bitcoin Core 29 and LND
[`8ea98fd52268`](https://github.com/lightningnetwork/lnd/commit/8ea98fd522683648144dd4f0f014fce80e311630).
The public SDK suite compiles against that upstream revision independently of
any consuming integration's client dependency.

## Delivered structure

The implementation consolidates tightly coupled protocol state in
`internal/server`: round, OOR, indexer, mailbox, swap and credit handlers share
one atomic state transition. `internal/store` persists a versioned state
snapshot in SQLite, and `internal/backend` provides Bitcoin RPC and LND clients.
The process entry point is `cmd/wl-regtest-server`; public integration tests are
in `itest` and the Bitcoin-backed server tests.

Ark signing keys are derived from a persisted operator seed with separate
purpose identifiers. LND owns the funded treasury coins and signs their wallet
inputs. MuSig2 nonce and signature transcripts are persisted with the associated
round before publication. This keeps the regtest implementation small without
requiring LND to retain remote Ark signing sessions.

The client edge is plaintext gRPC on regtest. LND uses its TLS certificate and
macaroon. Endpoint and data-directory configuration is exposed by the command;
protocol timing and economic defaults live in `server.DefaultConfig`.

## Verified behavior

| Layer | Verification |
| --- | --- |
| Public SDK | Fresh external-seed wallet, on-chain boarding, Lightning onboarding of an empty wallet through a same-operator invoice, ordinary OOR transfer and confirmed collaborative exit. |
| Bitcoin Core | CSV timeout sweep rejected before maturity and confirmed after maturity; backing-output admission fails during an invalidate/reconsider cycle and resumes afterward. |
| Wallet integration | Account initialization and reopening, on-chain boarding, two-wallet OOR with replay, ordinary refresh, collaborative exit, offline unilateral exit. |
| Lightning integration | External send/receive with actual invoice/payment settlement; bidirectional Wavelength/Arkade swaps through Lightning; same-operator vHTLC settlement; cooperative refund of a failed held invoice. |
| Credits | Ark and Lightning topups, redemption/replay, dust credit-only send, mixed credit/VTXO send, external and same-operator credit-assisted receives. |
| Recovery integration | Abrupt operator restart across credit operations, external receive after restart, LND restart after invoice issuance, pending-payment vHTLC refresh with three participant signatures, offline sender-only vHTLC refund with real CLTV/CSV and CPFP. |
| Focused server tests | Authentication and account isolation, replay binding, nonce transcript recovery, signature/value validation, connector forfeits, credit conservation, canonical multi-input treasury funding, multipart admission and ACK gating, expired receive rejection before funding, persisted on-chain preimage recovery. |

All transaction-bearing integration assertions use the public client together
with independent Bitcoin Core or Lightning settlement observations. Invalid
signatures, expired funding windows and unavailable backing outputs are rejected;
no success path manufactures balances, confirmations or preimages.

Use `make test-race`, `make fmt-check`, `go vet ./...` and `make itest` for the
public checks. The standalone Compose fixture and funding commands are in the
README. CI builds the operator image and checks Go formatting, races, vet and
SDK compilation; running the funded integration fixture remains explicit.

## Validation record

On September 6, 2026, a fresh consuming regtest stack passed all 21 selected
tests in 288 seconds: 18 Wavelength tests and the existing on-chain and
other-provider Lightning send/receive tests. The standalone public SDK suite
also passed, together with the Bitcoin CSV/reorg test. Server race tests,
`go vet`, the standalone build and `goformat` checks passed.

After the project rename, the public SDK, Bitcoin CSV/reorg checks, server
race tests, build, vet and formatting checks passed again. Replacing the image
against an existing database preserved the operator public key. The normal
21-test consuming integration sequence passed again in 272 seconds using the
renamed images. Cross-provider tests require spendable counterparty VTXOs and
propagated Lightning routes; isolated runs must provision those prerequisites.

The tested Docker images are published as:

- `guggero/wl-regtest-server:dev`, digest
  `sha256:43ebc3de7dc5fe072930220541a7a8ab4343cb7a8163eb4cd8574cc16fb64901`.
- `guggero/wl-regtest-lnd:8ea98fd`, digest
  `sha256:1e43c52d8eda80a59f349c7f70af22e3157ccb84b8549d0362157fbae6df6d1e`.

## Limits

This is a minimal regtest operator. It admits one intent per round, subsidizes
mining fees from its real treasury, charges no service fee and uses one dedicated
Lightning backend. Ordinary Loop products and production batching economics are
excluded. Expiry recovery handles unspent batch roots; reclaiming every branch
of a partially unrolled tree is not implemented.

A client must retain its completed funding package and confirmed fee inputs for
an offline exit. Dormant recovery arming occurs earlier than final funding
acknowledgement, so the recovery test waits for that acknowledgement before
removing the operator. Shallow backing-output reorg handling is tested; this
suite does not claim exhaustive adversarial reorg or fault-interleaving coverage.
