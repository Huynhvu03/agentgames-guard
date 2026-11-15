# LogiGuard — Wallet & Transaction Guard

Read-only guard for zkVerify **Agent Games Season 01, Wildcard track**.
Agent name: **LogiGuard** · Event ends **21/11/2026**.

## Live demo

- Demo: https://spreading-cds-prairie-send.trycloudflare.com/ (try the vitalik.eth DAI → Uniswap Permit2 example, flagged RISKY)
- Agent endpoint (POST /guard): https://spreading-cds-prairie-send.trycloudflare.com/guard
- Demo thread on X: https://x.com/0xlogi_/status/2121869977703895071
- Wildcard submission: filed 15/11/2026, status PENDING (manual review; results at the November closing event)

## The problem

Most wallet drains start with a single bad approval. A user signs an
unlimited ERC-20 allowance — or a `setApprovalForAll` — to a malicious
contract, and the attacker empties the wallet later, sometimes months
after the signature. Wallets show raw hex, so people sign blind.
LogiGuard screens an approval or a transaction **before** it is signed,
in plain language, using only public on-chain data.

## Who it helps

- **Everyday wallet users** who approve tokens to DEXes, NFT marketplaces
  and new protocols and want to know what they are actually signing.
- **Support / community mods** who check suspicious approvals for others.
- **Developers** who want a tiny, auditable screening service they can
  run themselves — no API key, no account, no funds involved.

## How it works

Plain Node.js (no framework), one dependency (`dotenv`). Three endpoints:

- `GET /health` — `{"ok":true, "agent":"LogiGuard", ...}` plus the live
  chain id and the RPC that answered.
- `GET /` — demo page with two forms and worked examples.
- `POST /guard` — JSON body, two modes:

### Allowance mode

```json
{ "mode": "allowance", "token": "0x...", "owner": "0x...", "spender": "0x..." }
```

Reads the live allowance with `eth_call` (`allowance()`), plus the token
`symbol()` / `decimals()`, then checks the spender with `eth_getCode`
and `eth_getTransactionCount`.

### Transaction mode

```json
{ "mode": "transaction", "to": "0x...", "data": "0x...", "value": "0" }
```

Decodes the calldata selector **locally** (no RPC needed for the decode)
and screens the call. Known functions include `approve`, `transfer`,
`transferFrom`, `permit`, `increaseAllowance`, `decreaseAllowance`,
`setApprovalForAll`, `safeTransferFrom`, `mint`, `burn`, `withdraw`,
`deposit`, Uniswap swaps / liquidity, `multicall`, `execute`, `stake`,
`unstake`, `vote`, `delegate` and more. Unknown selectors get an honest
`UNKNOWN` verdict, never a guess.

## The exact checks

Allowance mode:

1. Token is a contract (a token address with no code is rejected with an
   honest error — `allowance()` does not exist there).
2. Allowance size — 0, bounded, or unlimited (exactly 2^256 − 1).
3. Spender type — contract, EOA, or **EIP-7702 delegated EOA**
   (an EOA carrying a `0xef0100` delegation is still key-controlled, so
   it is treated as an EOA, and the delegation target is reported).
4. Spender activity — transaction count, reported as a weak signal only.

Transaction mode:

1. Target has code — a function call to an EOA does nothing on-chain
   (common in spoofed-token scams) and is flagged DANGEROUS.
2. EIP-7702 target — the call executes the delegate's code; the delegate
   address is reported and screening continues.
3. Selector recognised — unknown selectors return UNKNOWN.
4. Approval size — unlimited vs bounded, for `approve`,
   `increaseAllowance` and `permit`.
5. Spender / operator type — contract vs EOA (incl. 7702).
6. `permit` note — a permit is an off-chain signature; no on-chain
   approve transaction is needed, so a signed permit is as powerful as
   the approval itself.
7. `setApprovalForAll(true)` — grants control over an entire NFT
   collection; flagged DANGEROUS for an EOA operator.
8. ETH attached — token functions usually carry 0 ETH; attached ETH is
   flagged as a warning.

Verdicts: `SAFE` / `RISKY` / `DANGEROUS` / `UNKNOWN`. Every response
lists the checks run, their results, the decoded values, the RPC used,
the latency, and a limitations block.

## What it can and cannot do

Can: read live allowances, decode common calldata, tell a contract from
an EOA (including 7702 delegations), flag unlimited approvals, approvals
to EOAs, NFT operator grants, and calls to addresses with no code.

Cannot: detect honeypots or malicious token logic (that needs source-code
analysis); check Etherscan contract verification (no API key is used by
design); screen other chains (mainnet only for now); show prices (no
price data); tell a legitimate contract from a scam contract without
verified source code — an unlimited approval is risky either way.

It **never** signs anything, never sends transactions, never touches
private keys or seed phrases. It only reads public state through public
no-key RPCs.

## Run it

```bash
git clone https://github.com/Huynhvu03/agentgames-guard.git
cd agentgames-guard
npm install
cp .env.example .env   # optional: set RPC_URL, PORT (default 3001)
npm start
curl http://localhost:3001/health
```

RPC endpoints (no key): primary `https://ethereum.publicnode.com`,
fallback `https://eth.llamarpc.com` (configurable via `RPC_URL`).
Note: `https://rpc.ankr.com/eth` now requires an API key and is NOT
used. If every RPC fails, the agent returns an honest 502 error — it
never fabricates allowances, balances or verdicts.

## Test results (live Ethereum mainnet, 2026-11-15)

`node test-guard.js` — **8/8 checks passed** (total ~7 s):

| Case | Result |
|---|---|
| GET /health | chain_id 1 via publicnode |
| GET / demo page | 200, renders |
| Allowance, USDC/DAI/USDT/WETH vitalik.eth → Uniswap V2 router | SAFE, allowance 0 (live) |
| Allowance, USDC vitalik.eth → V3 router / 1inch | SAFE, allowance 0 (live) |
| **Allowance, DAI vitalik.eth → Uniswap Permit2** | **RISKY — unlimited (2^256 − 1), live** |
| approve unlimited → V2 router (USDC) | RISKY, decoded spender + amount |
| approve 100 USDC → V2 router | SAFE |
| approve unlimited → EOA (vitalik.eth) | DANGEROUS |
| transfer 1 USDC | SAFE |
| setApprovalForAll(true) → EOA | DANGEROUS |
| permit unlimited → V2 router | RISKY (7-param decode incl. v/r/s) |
| unknown selector 0xdeadbeef | UNKNOWN, no guess |
| approve calldata to 7702 EOA target | RISKY + delegation warning |
| approve with 1 ETH attached | SAFE + ETH warning |
| Bad address / bad mode / short calldata | 400 each |

Typical guard latency: **79–965 ms** per call.

Known incident, fixed honestly: the first test run (before the fix) saw
all three default RPCs time out from this VM, so every guard call
returned an honest 502 instead of a verdict. Diagnosis: Ankr now
requires an API key (removed), LlamaRPC returns HTTP 525 through this
VM's egress proxy (kept as fallback only), and only PublicNode answered
reliably — so the default order was changed to PublicNode first, the
fetch timeout was raised 8 s → 15 s, and the chain id is now cached.
No results were fabricated at any point.

## Files

- `server.js` — the agent (GET /health, GET / demo page, POST /guard)
- `test-guard.js` — live-mainnet test suite (`npm test`)
- `package.json` — one dependency: `dotenv`
- `.env.example`, `.gitignore`
- `README.md` — this file
- `SUBMISSION.md` — Wildcard submission fields, ready to paste
- `README-WINDOWS-GUARD.md` — run steps for the owner's Windows PC
