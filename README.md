# wl-regtest-server

A Go implementation of the public Wavelength operator and swap protocols for
Bitcoin regtest integration testing. It creates real commitment transactions,
MuSig2-signed VTXO trees, checkpoint transactions, vHTLCs and Lightning payments.
Bitcoin Core validates broadcasts and the Wavelength client validates the
operator's transaction proposals and signatures.

The operator processes one client intent per round, charges no service fees,
and funds swaps from a small pool of real operator-owned VTXOs. Credits are a
persistent custodial ledger backed by received Lightning payments or Ark topups.
It does not implement ordinary Loop products or production batching economics.

## Dependencies

- Go 1.27.3, for a local build.
- Bitcoin Core 29 with `regtest`, `txindex`, wallet RPC and package relay enabled.
- A dedicated, synchronized LND on the same regtest chain, funded on-chain and
  with a funded Lightning channel. Start it with `--requireinterceptor`.
- A regtest Esplora endpoint for client wallets.

The tested LND revision is
[`8ea98fd52268`](https://github.com/lightningnetwork/lnd/commit/8ea98fd522683648144dd4f0f014fce80e311630).
Build its image with:

```sh
docker build -f docker/lnd.Dockerfile -t guggero/wl-regtest-lnd:8ea98fd .
```

The server pins the public Wavelength client at
[`1475c1beb832`](https://github.com/lightninglabs/wavelength/commit/1475c1beb8326017a00833aa752ca1919ae7dc61).
No local module replacements or closed server sources are required.

## Run

```sh
export BITCOIN_RPC_URL=http://host.docker.internal:18443
export BITCOIN_RPC_USER=regtest
export BITCOIN_RPC_PASSWORD=regtest
export LND_RPC_ADDRESS=host.docker.internal:10009
export LND_DATA_DIR=/absolute/path/to/lnd

docker compose -f docker/compose.yml up --build -d
```

The LND TLS certificate must cover the hostname used in `LND_RPC_ADDRESS`.
The Compose example connects to existing Bitcoin/LND services and retains the
operator's SQLite database in a named volume. The operator rejects other Bitcoin
networks. Its gRPC edge uses plaintext for local testing; the example binds only
to localhost. Configure clients with Ark and swap address `127.0.0.1:10010`,
regtest, insecure transport and the local Esplora URL.

After startup, mine a block to confirm the operator's initial inventory round.
Inventory contains eight independent leaves and is replenished as funds are
consumed; its initial commitment uses 0.1 BTC plus mining fees. Boarding and
refresh rounds also need operator wallet funds for fees. The node's Lightning
channel needs outbound liquidity for sends and inbound liquidity for receives.

For a local binary, run `make build` and `bin/wl-regtest-server --help`.
Configuration flags have environment equivalents shown in the Compose file.
`--healthcheck --listen=127.0.0.1:10010` probes the RPC process; availability of
confirmed inventory and Lightning routes is checked by the applicable flows.

## Standalone regtest fixture

The public fixture runs Bitcoin Core, Esplora, the dedicated operator LND and
an external Lightning peer on an isolated Compose network. It uses host ports
18453, 3010 and 10020, distinct from the attach-mode defaults. Docker Compose,
Bash and `jq` are required for fixture funding.

```sh
docker compose -f docker/regtest.yml up --build -d
bash docker/fund-regtest.sh
export WL_TEST_BITCOIN_RPC=http://127.0.0.1:18453/wallet/miner
export WL_TEST_BITCOIN_USER=regtest
export WL_TEST_BITCOIN_PASSWORD=regtest
export WL_TEST_ESPLORA=http://127.0.0.1:3010
export WL_TEST_SERVER=127.0.0.1:10020
make itest
```

The funding script creates the miner wallet, mines mature coins, funds both
Lightning wallets and opens a bidirectional channel. Run it after creating a
fresh fixture. Start/stop the same Compose project to retain its state; use
`docker compose -f docker/regtest.yml down --volumes` to discard that fixture.
The `WL_BITCOIN_PORT`, `WL_ESPLORA_PORT` and `WL_SERVER_PORT` variables override
host ports; use matching client test endpoints when overriding them.

## Validate

```sh
make test
make test-race
make fmt-check

# Supply a funded operator, Esplora and a funded Bitcoin wallet RPC.
export WL_TEST_BITCOIN_RPC=http://127.0.0.1:18443
export WL_TEST_BITCOIN_USER=regtest
export WL_TEST_BITCOIN_PASSWORD=regtest
export WL_TEST_ESPLORA=http://127.0.0.1:3000
export WL_TEST_SERVER=127.0.0.1:10010
make itest
```

The Bitcoin integration test checks that Core rejects an immature branch
timeout sweep, then accepts and confirms it at CSV maturity. The public SDK
test boards a wallet, pays an invoice to an empty wallet on the
same Ark, transfers VTXOs and verifies a collaborative exit's confirmed Bitcoin
output. It mines regtest blocks and spends the fixture's test funds.

The consuming regtest integration suite additionally exercises external
Lightning send/receive, credit topups/redemption, dust and mixed credit payments,
credit-assisted receives, cooperative swap refunds, vHTLC participant signing and refresh, unilateral exit
with the operator offline, bidirectional Wavelength/Arkade payments through
Lightning, and abrupt operator restarts. Server unit tests cover
signature validation, authenticated replay, nonce transcript persistence,
credit conservation and chain-state reconciliation.

The design and wider acceptance matrix are in
[the implementation plan](docs/implementation-plan.md).

## Persistence and operating limits

Keep `/data` with its seed and SQLite database across container replacements.
The server commits request outcomes, mailbox events, reservations and signing
transcripts before returning success. Replays use the same transaction and
nonce material. Deleting the volume creates a new operator identity.

This implementation intentionally uses one intent per round, a fixed regtest
mining subsidy, zero service fees and plaintext client RPC. Timing and amount
limits are defined in `server.DefaultConfig`. Operator timeout recovery sweeps
unspent batch roots; reclaiming every output of a partially unrolled tree and
production treasury management are outside this minimal test operator.

Unilateral recovery requires the client to retain its complete signed funding
package and hold sufficient confirmed on-chain fee inputs. A dormant vHTLC
recovery row can precede completion of the funding exchange; it is not itself
proof that the client has received every final signature.
