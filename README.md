# ant-wasm-client

A browser client for Autonomi-style storage nodes, written in Rust and compiled to
WebAssembly: the page opens its **own WebRTC connections directly to nodes**, fetches
content-addressed chunks, verifies and decrypts them locally, and can pay for and store
new data. No browser extension, no local daemon, no gateway, no server relaying anyone's
bytes.

**Live demo: [webrtc-demo.autonomi.space](https://webrtc-demo.autonomi.space)** — the
`web/` page in this repo, served as static files against a public 20-node test devnet
running **RFC 9443 single-port mode**: each node serves QUIC and WebRTC on one UDP
socket.

> Unofficial community project. Not operated by, affiliated with, or endorsed by
> Autonomi. It talks to a demo devnet, not to the live Autonomi network.

Design notes, findings and the node-side change live in the umbrella repo:
**[rid-dim/autonomi-webrtc-test-setup](https://github.com/rid-dim/autonomi-webrtc-test-setup)**.

## What it does

- **Download** — resolve a public 64-hex address to its data map, fetch every chunk
  **directly from the peers responsible for it**, and verify each one against its BLAKE3
  content address before use. A node can refuse to serve, but it cannot return different
  bytes. Chunks of one round are fetched **concurrently**, each over its own connection;
  shrunk (multi-level) data maps are resolved round by round, so large files work.
  Self-decryption runs in WASM.
- **Upload** — self-encrypt in the browser, request quotes from the close group
  (each quote's ML-DSA-65 signature and its peer binding are verified client-side),
  build the ERC-20 `approve` + `payForQuotes` calldata, and `PUT` the chunks with the
  resulting `ProofOfPayment` to the storing nodes, which check the payment on-chain.
  The client **never signs or broadcasts**: it hands `(to, calldata)` to a JS callback,
  so the page can use MetaMask or — on a devnet — an unlocked Anvil account with no
  wallet UI at all.
- **Discovery + connection pool** — one bootstrap connection answers "who is closest to
  this address"; every further request goes over a direct connection to that peer,
  opened on demand and reused.
- **PQC tunnel** — every node session is wrapped in an application-layer tunnel:
  ML-KEM-768 key establishment, ML-DSA-65 node authentication with PeerId pinning
  (PeerId = BLAKE3 of the node's ML-DSA public key), ChaCha20-Poly1305 for the payload.
  The node's DTLS certificate is pinned by SHA-256 fingerprint, so no CA is involved.
- **ICE signaling for NAT'd nodes** — `relayed_fetch()` reaches a peer that is not
  directly dialable by relaying SDP through the bootstrap node and using a STUN
  reflector (verified on loopback; cone NAT is the target, symmetric NAT is out of
  scope).
- **Demo page** (`web/index.html`) — connection form, manual download by address,
  upload with payment-path selection, and an optional **gallery** that loads files from
  the network and renders images/audio inline, with per-item stats (chunks, nodes,
  throughput, elapsed).
- **Auto-loaded page content** — if the catalogue names them, the page's **background
  image** and the **explainer figure** are fetched over the same WebRTC path on load,
  with no click: the backdrop fades in behind a shade that preserves text contrast, the
  figure's space is reserved by a placeholder so nothing shifts when it arrives, and both
  carry the accent frame and a provenance badge ("⚡ … n chunks from m nodes, t s").
  Everything network-loaded is marked in one accent colour that page furniture never
  uses. Failures are silent apart from a single log line — the page then looks exactly as
  it does without a catalogue.

### JS API in short

```js
import init, { WasmClient, content_address } from "./pkg/ant_wasm_client.js";
await init();

const client = await WasmClient.connect(ip, port, certHashHex, peerIdHex);
const bytes  = await client.download(addressHex);   // verified + decrypted
client.chunk_count;        // chunks the last download pulled off the network
client.connection_count;   // open direct node connections

// upload: `pay` is (toHex, calldataHex) => Promise<txHashHex>
const address = await client.upload(data, tokenAddrHex, vaultAddrHex, pay);
```

Full signatures: `web/pkg/ant_wasm_client.d.ts` after a build.

## Build

Prerequisites: a Rust toolchain, the `wasm32-unknown-unknown` target, and
`wasm-bindgen-cli` **0.2.126** (the `wasm-bindgen` dependency is pinned to `=0.2.126`;
a mismatched CLI fails the bindgen step).

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.126

cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir web/pkg \
    target/wasm32-unknown-unknown/release/ant_wasm_client.wasm
```

`.cargo/config.toml` pins `MAX_CHUNK_SIZE` (self-encryption reads it via `option_env!`
at **compile** time) to the network's value — don't override it in the environment, or
the chunking silently stops matching the network.

## Deploy (static hosting)

Everything is static and self-contained; no CDN, no build step beyond the two commands
above. Serve `web/` (or copy these files):

```
index.html                        the whole app (inline ES module, no external assets)
pkg/ant_wasm_client.js
pkg/ant_wasm_client_bg.wasm       serve as application/wasm
pkg/*.d.ts                        optional, types only
devnet-manifest.json              required — bootstrap node + webrtc {address, cert_hash, peer_id}
demo-catalogue.json               optional — gallery, background and figure; absent (404) hides them
```

- The **public** manifest is the devnet manifest with the `evm` section stripped
  (no `wallet_private_key`, no RPC URL). The page detects this and runs download-only:
  the upload fieldset is hidden, or — if `evm` is present but the key is not — the
  keyless Anvil payer is disabled and MetaMask remains as the only payment path.
- `demo-catalogue.json` schema and an example are in
  [`web/demo-catalogue.json.example`](web/demo-catalogue.json.example):
  `{"items":[{"title","address","type","filename"}], "background"?: {...}, "figure"?: {...}}`.
  For `items`, `type` decides the rendering (`image/*` inline, `audio/*` with controls,
  anything else a save link). The optional `background` (`{title, address, type}`) is
  auto-loaded on page open and faded in as the page backdrop; the optional `figure`
  (same shape, SVG or bitmap) is auto-loaded into the intro section with the accent frame
  and badge. Both are fetched over the network like everything else, both are optional,
  and a failure of either leaves the rest of the page untouched.
- The demo page has no backend of any kind — any static host will do.

## Local development against a devnet

Needs the node fork with the WebRTC listener
([rid-dim/ant-node](https://github.com/rid-dim/ant-node), branch
`feat/rfc9443-single-port-prep`) and `anvil` (foundry) on `PATH`:

```sh
# 1. build node + devnet helper (from the ant-node checkout)
cargo build --release --features webrtc

# 2. run a local devnet with an EVM chain and a WebRTC listener
./target/release/ant-devnet --preset small --enable-evm \
    --webrtc-port 25000 --manifest /tmp/devnet.json --data-dir /tmp/devnet
#   …or --webrtc-single-port to share the node's existing UDP port (RFC 9443 mode)

# 3. build this client and serve the page
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir web/pkg \
    target/wasm32-unknown-unknown/release/ant_wasm_client.wasm
cp /tmp/devnet.json web/devnet-manifest.json     # keeps the evm section → upload works
python3 -m http.server 8080 --directory web      # open http://127.0.0.1:8080
```

The page auto-loads `./devnet-manifest.json` on start and fills in node address, cert
hash and peer id; any other manifest URL can be pasted into the form. With the `evm`
section present, uploads pay through the devnet's unlocked Anvil account without any
wallet interaction; MetaMask can be selected instead (the page adds the devnet chain).

To fill the gallery, upload some files with the native CLI
(`SECRET_KEY=<manifest wallet key> ant --devnet-manifest /tmp/devnet.json
--allow-loopback --evm-network local file upload <file> --public`) and put the returned
addresses into `web/demo-catalogue.json` — as `items`, and optionally as `background`
(a photo) and `figure` (a diagram).

## Repo layout

| Path | What it is |
|---|---|
| `src/lib.rs` | `WasmClient` — the JS-facing API: connect, download, upload, discovery, `relayed_fetch` |
| `src/conn.rs`, `src/webrtc.rs`, `src/sdp.rs` | WebRTC-Direct connection setup, certificate pinning, SDP munging, ICE signaling |
| `src/tunnel.rs` | the PQC tunnel (ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305) |
| `src/protocol.rs`, `src/framing.rs` | the node wire protocol (tagged `ChunkMessage`) and framing |
| `src/retrieval.rs` | verified retrieval state machine: address verification, data-map walking, self-decryption |
| `src/payment.rs`, `src/evm.rs` | quote parsing/verification, payment split, ABI calldata for `approve`/`payForQuotes` |
| `src/discovery.rs` | closest-peer lookups via the bootstrap connection |
| `web/` | the demo page (`index.html`), the catalogue example, the generated `pkg/` |
| `tests/` | wire-format tests against fixtures generated from the native types |

## Tests

```sh
cargo test          # 17 tests: 10 unit + 7 payment-wire fixture tests
```

The fixture tests pin the payment wire format (quote encoding, quote hash, tagged
single-node proof) byte-for-byte against the native implementation, so a drift upstream
shows up here instead of on the network.

## Credits

- **Nic Dorman** — [`exp-ant-wasm`](https://github.com/Nic-dorman/exp-ant-wasm): the
  application-layer PQC tunnel (ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305) and the
  browser-direct architecture this client ports to WebRTC.
- **Mick ([@mickvandijke](https://github.com/mickvandijke))** — the WASM bindings and MetaMask/JS payment groundwork in the
  Autonomi codebase, and the earlier WebRTC experiment that mapped out the terrain.
- The **Autonomi** and **saorsa** teams for the node stack, self-encryption, and the
  transport work everything here builds on.

## License

`Cargo.toml` declares `MIT OR Apache-2.0`. TODO: add the corresponding `LICENSE-MIT`
and `LICENSE-APACHE` files — the repo currently ships none.
