# LogiGuard — Wildcard Submission (Agent Games Season 01)

Fields copied from the Wildcard submission form, in order. Fill in the
placeholders in angle brackets before submitting.

## 1. PROJECT TITLE *

LogiGuard — Wallet & Transaction Guard

## 2. GITHUB REPOSITORY LINK *

https://github.com/Huynhvu03/agentgames-guard

(The repo does not exist yet; it will be created when the code is uploaded.)

## 3. AGENT ENDPOINT

https://<tunnel>/guard

(Replace <tunnel> with the public cloudflared URL once the second tunnel
is running, e.g. https://<name>.trycloudflare.com/guard. The demo page
is at the same host root, GET /.)

## 4. WHAT IT DOES * (MAX 2000 characters)

LogiGuard is a read-only wallet and transaction guard. The problem: most wallet drains start with one bad approval - a user signs an unlimited ERC-20 allowance or a setApprovalForAll to a malicious contract, and the attacker empties the wallet later. Wallets show raw hex, so people sign blind. LogiGuard screens an approval or transaction BEFORE signing. POST /guard with {mode:'allowance', token, owner, spender} reads the live on-chain allowance, token symbol and decimals, and checks whether the spender is a contract, an EOA, or an EIP-7702 delegated account. With {mode:'transaction', to, data, value} it decodes the calldata locally (approve, transfer, permit, setApprovalForAll, swaps and more), checks the target has code, and flags unlimited approvals, approvals to EOAs, NFT operator grants, and unknown selectors. Every verdict (SAFE / RISKY / DANGEROUS / UNKNOWN) lists the exact checks run and what the agent cannot do. It never signs, sends transactions, or touches private keys, and uses only public no-key RPCs. A demo page at GET / lets anyone try it with a real example: vitalik.eth's unlimited DAI allowance to Uniswap Permit2, flagged RISKY. zkVerify note: v1 has no zk proof. Screening is deterministic over public on-chain inputs, so a Groth16 proof that a verdict was computed correctly from those inputs is a natural next step; agents without zkVerify remain eligible.

## 5. PROOF REFERENCE

(Blank — no proof reference in v1.)

## 6. ADDITIONAL LINKS (one URL per line)

https://<tunnel>/guard
https://<tunnel>/
https://github.com/Huynhvu03/agentgames-guard
https://x.com/0xlogi_/status/<demo-thread-post-id>

(Replace <tunnel> with the live tunnel URL; replace <demo-thread-post-id>
with the demo post link if one is published for the public-share bonus.)

## 7. MESSAGE TO JUDGES (MAX 1000 characters)

LogiGuard screens approvals and transactions before signing, using only public on-chain reads. No keys, no signing, no funds ever move. It flags unlimited allowances, approvals to EOAs, NFT operator grants, and unknown calldata, and says plainly what it cannot check (honeypots, unverified source code). Tested end-to-end against live Ethereum mainnet: real allowances, real calldata decodes, 8/8 checks passing. v1 has no zkVerify proof; the screening is deterministic over public inputs, so a proof of correct screening is the natural next step.
