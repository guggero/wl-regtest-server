#!/usr/bin/env bash
# Fund only the explicitly selected standalone regtest Compose project.
set -euo pipefail
cd "$(dirname "$0")"
compose=(docker compose -f regtest.yml)
btc() { "${compose[@]}" exec -T bitcoin bitcoin-cli -regtest -rpcuser=regtest -rpcpassword=regtest "$@"; }
ln() { local node=$1; shift; "${compose[@]}" exec -T "$node" lncli --network=regtest "$@"; }
wait_for() {
  for ((attempt=0; attempt<120; attempt++)); do
    if "$@" >/dev/null 2>&1; then return; fi
    sleep 1
  done
  echo "Timed out waiting for $*" >&2
  return 1
}
wait_for btc getblockchaininfo
if ! btc listwallets | jq -e 'index("miner") != null' >/dev/null; then
  if ! btc loadwallet miner; then btc createwallet miner; fi
fi
miner=$(btc -rpcwallet=miner getnewaddress)
btc generatetoaddress 101 "$miner" >/dev/null
for node in lnd peer; do
  wait_for ln "$node" getinfo
  address=$(ln "$node" newaddress p2tr | jq -r .address)
  btc -rpcwallet=miner sendtoaddress "$address" 2 >/dev/null
done
btc generatetoaddress 6 "$miner" >/dev/null
synced() { ln "$1" getinfo | jq -e '.synced_to_chain == true' >/dev/null; }
wait_for synced lnd
wait_for synced peer
peer=$(ln peer getinfo | jq -r .identity_pubkey)
if ! ln lnd listchannels | jq -e --arg peer "$peer" '.channels[] | select(.remote_pubkey == $peer and .active)' >/dev/null; then
  ln lnd connect "$peer@peer:9735" || true
  connected() { ln lnd listpeers | jq -e --arg peer "$peer" '.peers[] | select(.pub_key == $peer)' >/dev/null; }
  wait_for connected
  ln lnd openchannel --node_key="$peer" --local_amt=10000000 --push_amt=5000000 --sat_per_vbyte=10
  btc generatetoaddress 6 "$miner" >/dev/null
fi
wait_for "${compose[@]}" exec -T wavelength wl-regtest-server --healthcheck --listen=127.0.0.1:10010
# Confirm inventory after the operator has observed its funded wallet.
inventory() { btc getrawmempool | jq -e 'length > 0' >/dev/null; }
wait_for inventory
btc generatetoaddress 1 "$miner" >/dev/null
echo "Funded regtest fixture. Run make itest with the standalone endpoints in README.md."
