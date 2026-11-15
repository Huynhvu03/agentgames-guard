/**
 * LogiGuard — Wallet & transaction guard for zkVerify Agent Games (Wildcard track).
 *
 * READ-ONLY by design. This agent NEVER signs anything, NEVER sends
 * transactions, NEVER touches private keys or seed phrases. It only reads
 * public Ethereum mainnet state through public JSON-RPC endpoints and
 * decodes calldata locally, so a user can screen an approval or a
 * transaction BEFORE signing it.
 *
 * Endpoints:
 *   GET  /health  -> {"ok":true, "agent":"LogiGuard", ...}
 *   GET  /        -> demo HTML page (two forms + worked examples)
 *   POST /guard   -> JSON {mode:"allowance"|"transaction", ...}
 *
 * Env (see .env.example):
 *   RPC_URL  - primary public Ethereum RPC (default https://eth.llamarpc.com)
 *   PORT     - default 3001
 *
 * No framework, Node 20+ built-in fetch. Only dependency: dotenv.
 */
'use strict';

try { require('dotenv').config(); } catch (_) { /* dotenv not installed */ }

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '3001', 10);

const DEFAULT_RPCS = [
  // Verified working from this VM (2026-11-15): publicnode answers in ~200-400 ms.
  'https://ethereum.publicnode.com',
  // Standard public endpoint; returns HTTP 525 through this VM's egress
  // proxy, but works on normal networks — kept as a fallback only.
  'https://eth.llamarpc.com',
];
const RPCS = [...new Set(
  [process.env.RPC_URL || DEFAULT_RPCS[0], ...DEFAULT_RPCS].filter(Boolean)
)];

const MAX_UINT256 = (1n << 256n) - 1n;
const FETCH_TIMEOUT_MS = 15000;
const MAX_BODY_BYTES = 64 * 1024;

// Cached chain id (a given RPC does not change chains).
let cachedChainId = null;

const LIMITATIONS = [
  'Cannot detect honeypots or malicious token logic (that needs source-code analysis).',
  'Cannot check Etherscan contract verification — no API key is used by design.',
  'Mainnet only for now (chain id 1); other chains are not screened.',
  'No price data — amounts are shown in token units, not USD.',
  'A contract spender can be a legitimate protocol or a scam; without verified source code the agent cannot tell the difference — treat any unlimited approval as risky.',
  'The agent never signs anything and never sees private keys; it only reads public on-chain state.',
];

// ---------------------------------------------------------------------------
// JSON-RPC helpers (public endpoints only, with fallback)
// ---------------------------------------------------------------------------

async function rpcCall(method, params) {
  const errors = [];
  for (const rpc of RPCS) {
    const started = Date.now();
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      const res = await fetch(rpc, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (json.error) throw new Error(json.error.message || 'RPC error');
      if (json.result === undefined || json.result === null) {
        throw new Error('empty result');
      }
      return { result: json.result, rpc, ms: Date.now() - started };
    } catch (e) {
      errors.push(`${rpc}: ${e.message}`);
    }
  }
  const err = new Error('All RPC endpoints failed');
  err.details = errors;
  throw err;
}

const hexToBigInt = (hex) => BigInt(hex);
const isAddress = (s) => typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);
const isHexData = (s) => typeof s === 'string' && /^0x([0-9a-fA-F]{2})*$/.test(s);
const pad32 = (hexNoPrefix) => hexNoPrefix.toLowerCase().padStart(64, '0');

function ethCall(to, data) {
  return rpcCall('eth_call', [{ to, data }, 'latest']);
}

async function getCode(address) {
  const { result, rpc, ms } = await rpcCall('eth_getCode', [address, 'latest']);
  const code = result;
  // EIP-7702: an EOA can carry a 23-byte delegation indicator
  // (0xef0100 + 20-byte delegate address). It is still a key-controlled
  // account — NOT a contract — so it must not be classified as one.
  let kind = 'contract';
  let delegationTarget = null;
  if (code === '0x') kind = 'eoa';
  else if (/^0xef0100[0-9a-fA-F]{40}$/.test(code)) {
    kind = 'eoa7702';
    delegationTarget = '0x' + code.slice(8);
  }
  return { code, kind, isContract: kind === 'contract', delegationTarget, codeBytes: (code.length - 2) / 2, rpc, ms };
}

async function getTxCount(address) {
  const { result } = await rpcCall('eth_getTransactionCount', [address, 'latest']);
  return Number(hexToBigInt(result));
}

async function getChainId() {
  if (cachedChainId !== null) return cachedChainId;
  const { result } = await rpcCall('eth_chainId', []);
  cachedChainId = Number(hexToBigInt(result));
  return cachedChainId;
}

// Decode an ABI-encoded string return value; also handles bytes32-style symbols.
function decodeStringResult(hex) {
  if (!hex || hex === '0x') return null;
  const bytes = Buffer.from(hex.slice(2), 'hex');
  if (bytes.length === 32) {
    // Possibly a bytes32 symbol (e.g. some older tokens).
    const s = bytes.toString('utf8').replace(/\0+$/, '');
    if (/^[\x20-\x7E]+$/.test(s) && s.length > 0) return s;
  }
  if (bytes.length < 64) return null;
  const len = Number(bytes.readBigUInt64BE(32));
  if (64 + len > bytes.length) return null;
  return bytes.subarray(64, 64 + len).toString('utf8');
}

function decodeUintResult(hex) {
  if (!hex || hex === '0x') return null;
  return hexToBigInt(hex);
}

function formatUnits(value, decimals) {
  const d = BigInt(decimals);
  const base = 10n ** d;
  const whole = value / base;
  const frac = (value % base).toString().padStart(Number(d), '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}

// ---------------------------------------------------------------------------
// Local calldata decoding (no RPC needed)
// ---------------------------------------------------------------------------

// type: address | uint256 | uint8 | bool | bytes32 | bytes | address[] | uint256[]
const SELECTORS = {
  '0x095ea7b3': { name: 'approve', params: [['spender', 'address'], ['amount', 'uint256']] },
  '0xa9059cbb': { name: 'transfer', params: [['to', 'address'], ['amount', 'uint256']] },
  '0x23b872dd': { name: 'transferFrom', params: [['from', 'address'], ['to', 'address'], ['amount', 'uint256']] },
  '0xd505accf': { name: 'permit', params: [['owner', 'address'], ['spender', 'address'], ['value', 'uint256'], ['deadline', 'uint256'], ['v', 'uint8'], ['r', 'bytes32'], ['s', 'bytes32']] },
  '0x39509351': { name: 'increaseAllowance', params: [['spender', 'address'], ['addedValue', 'uint256']] },
  '0xa457c2d7': { name: 'decreaseAllowance', params: [['spender', 'address'], ['subtractedValue', 'uint256']] },
  '0xa22cb465': { name: 'setApprovalForAll', params: [['operator', 'address'], ['approved', 'bool']] },
  '0x42842e0e': { name: 'safeTransferFrom', params: [['from', 'address'], ['to', 'address'], ['tokenId', 'uint256']] },
  '0xb88d4fde': { name: 'safeTransferFrom', params: [['from', 'address'], ['to', 'address'], ['tokenId', 'uint256'], ['data', 'bytes']] },
  '0x40c10f19': { name: 'mint', params: [['to', 'address'], ['amount', 'uint256']] },
  '0xa0712d68': { name: 'mint', params: [['amount', 'uint256']] },
  '0x42966c68': { name: 'burn', params: [['amount', 'uint256']] },
  '0x2e1a7d4d': { name: 'withdraw', params: [['amount', 'uint256']] },
  '0xd0e30db0': { name: 'deposit', params: [] },
  '0x7ff36ab5': { name: 'swapExactETHForTokens', params: [['amountOutMin', 'uint256'], ['path', 'address[]'], ['to', 'address'], ['deadline', 'uint256']] },
  '0x18cbafe5': { name: 'swapExactTokensForETH', params: [['amountIn', 'uint256'], ['amountOutMin', 'uint256'], ['path', 'address[]'], ['to', 'address'], ['deadline', 'uint256']] },
  '0x38ed1739': { name: 'swapExactTokensForTokens', params: [['amountIn', 'uint256'], ['amountOutMin', 'uint256'], ['path', 'address[]'], ['to', 'address'], ['deadline', 'uint256']] },
  '0x8803dbee': { name: 'swapExactTokensForTokensSupportingFeeOnTransferTokens', params: [['amountIn', 'uint256'], ['amountOutMin', 'uint256'], ['path', 'address[]'], ['to', 'address'], ['deadline', 'uint256']] },
  '0xe8e33700': { name: 'addLiquidity', params: [['tokenA', 'address'], ['tokenB', 'address'], ['amountADesired', 'uint256'], ['amountBDesired', 'uint256'], ['amountAMin', 'uint256'], ['amountBMin', 'uint256'], ['to', 'address'], ['deadline', 'uint256']] },
  '0xf305d719': { name: 'addLiquidityETH', params: [['token', 'address'], ['amountTokenDesired', 'uint256'], ['amountTokenMin', 'uint256'], ['amountETHMin', 'uint256'], ['to', 'address'], ['deadline', 'uint256']] },
  '0xbaa2abde': { name: 'removeLiquidity', params: [['tokenA', 'address'], ['tokenB', 'address'], ['liquidity', 'uint256'], ['amountAMin', 'uint256'], ['amountBMin', 'uint256'], ['to', 'address'], ['deadline', 'uint256']] },
  '0x5c11d795': { name: 'multicall', params: [['data', 'bytes']] },
  '0xac9650d8': { name: 'multicall', params: [['data', 'bytes']] },
  '0x3593564c': { name: 'execute', params: [['to', 'address'], ['value', 'uint256'], ['data', 'bytes']] },
  '0x3ccfd60b': { name: 'claim', params: [] },
  '0xa694fc3a': { name: 'stake', params: [['amount', 'uint256']] },
  '0x2e17de78': { name: 'unstake', params: [['amount', 'uint256']] },
  '0x6dd7d8ea': { name: 'vote', params: [['proposalId', 'uint256'], ['support', 'uint8']] },
  '0x5c19a95c': { name: 'delegate', params: [['delegatee', 'address']] },
};

const DYNAMIC = new Set(['bytes', 'address[]', 'uint256[]']);

function decodeParams(params, dataBuf) {
  // dataBuf: calldata WITHOUT the 4-byte selector.
  const out = {};
  const words = Math.floor(dataBuf.length / 32);
  params.forEach(([name, type], i) => {
    if (i >= words) { out[name] = null; return; }
    const word = dataBuf.subarray(i * 32, i * 32 + 32);
    if (type === 'address') {
      out[name] = '0x' + word.subarray(12).toString('hex');
    } else if (type === 'uint256') {
      out[name] = BigInt('0x' + word.toString('hex'));
    } else if (type === 'uint8' || type === 'bool') {
      const v = word[31];
      out[name] = type === 'bool' ? v !== 0 : v;
    } else if (type === 'bytes32') {
      out[name] = '0x' + word.toString('hex');
    } else if (DYNAMIC.has(type)) {
      const offset = Number(BigInt('0x' + word.toString('hex')));
      if (offset + 32 > dataBuf.length) { out[name] = null; return; }
      const len = Number(BigInt('0x' + dataBuf.subarray(offset, offset + 32).toString('hex')));
      if (type === 'bytes') {
        out[name] = '0x' + dataBuf.subarray(offset + 32, offset + 32 + len).toString('hex');
      } else {
        const arr = [];
        const elemSize = 32;
        for (let j = 0; j < len; j++) {
          const w = dataBuf.subarray(offset + 32 + j * elemSize, offset + 32 + (j + 1) * elemSize);
          if (w.length < 32) break;
          arr.push(type === 'address[]' ? '0x' + w.subarray(12).toString('hex') : BigInt('0x' + w.toString('hex')));
        }
        out[name] = arr;
      }
    } else {
      out[name] = null;
    }
  });
  return out;
}

function stringifyDecoded(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'bigint') out[k] = v.toString();
    else if (Array.isArray(v)) out[k] = v.map((x) => (typeof x === 'bigint' ? x.toString() : x));
    else out[k] = v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Verdict builders
// ---------------------------------------------------------------------------

function baseResult(mode) {
  return {
    agent: 'LogiGuard',
    mode,
    verdict: 'UNKNOWN',
    summary: '',
    reasons: [],
    checks: [],
    data: {},
    limitations: LIMITATIONS,
    chain_id: null,
    rpc_used: null,
    latency_ms: null,
  };
}

function check(id, label, status, detail) {
  return { id, label, status, detail };
}

// --- allowance mode ---------------------------------------------------------

async function guardAllowance(body) {
  const started = Date.now();
  const res = baseResult('allowance');
  const { token, owner, spender } = body;
  if (!isAddress(token) || !isAddress(owner) || !isAddress(spender)) {
    return { status: 400, body: { error: 'token, owner and spender must be 0x addresses (40 hex chars).', hint: 'Example token: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 (USDC).' } };
  }

  try {
    const chainId = await getChainId();
    res.chain_id = chainId;
    if (chainId !== 1) {
      res.checks.push(check('chain', 'Chain id', 'warn', `RPC reports chain id ${chainId}, not Ethereum mainnet (1). Results may not match mainnet.`));
    }

    // Token must be a contract, otherwise allowance() does not exist.
    const tokenCode = await getCode(token);
    res.rpc_used = tokenCode.rpc;
    if (!tokenCode.isContract) {
      return { status: 422, body: { error: 'token address has no code — it is not a contract, so allowance() does not exist there.', hint: 'Double-check the token address; a real ERC-20 token is always a contract.' } };
    }
    res.checks.push(check('token_contract', 'Token is a contract', 'pass', `${tokenCode.codeBytes} bytes of code at the token address.`));

    // allowance(owner, spender) — 0xdd62ed3e
    const allowanceData = '0xdd62ed3e' + pad32(owner.slice(2)) + pad32(spender.slice(2));
    const { result: allowanceHex, rpc } = await ethCall(token, allowanceData);
    res.rpc_used = rpc;
    const allowance = decodeUintResult(allowanceHex);
    if (allowance === null) throw new Error('allowance() returned empty data');

    // symbol() + decimals() — best effort, some tokens do not implement them.
    let symbol = null;
    let decimals = null;
    try {
      const s = await ethCall(token, '0x95d89b41');
      symbol = decodeStringResult(s.result);
    } catch (_) { /* leave null */ }
    try {
      const d = await ethCall(token, '0x313ce567');
      const v = decodeUintResult(d.result);
      decimals = v === null ? null : Number(v);
    } catch (_) { /* leave null */ }

    const isUnlimited = allowance === MAX_UINT256;
    const human = decimals !== null ? formatUnits(allowance, decimals) : allowance.toString();
    res.data = {
      token, owner, spender,
      symbol, decimals,
      allowance: allowance.toString(),
      allowance_human: decimals !== null ? `${human}${symbol ? ' ' + symbol : ''}` : `${human} (raw units; decimals unknown)`,
      is_unlimited: isUnlimited,
    };

    // Spender type: EOA vs contract (EIP-7702 delegated EOAs are still EOAs).
    const spenderCode = await getCode(spender);
    const spenderIsContract = spenderCode.isContract;
    res.data.spender_is_contract = spenderIsContract;
    res.data.spender_code_bytes = spenderCode.codeBytes;
    res.data.spender_kind = spenderCode.kind;
    if (spenderCode.kind === 'eoa7702') {
      res.data.spender_delegation_target = spenderCode.delegationTarget;
      res.checks.push(check('spender_type', 'Spender type', 'warn',
        `Spender is an EOA with an EIP-7702 delegation to ${spenderCode.delegationTarget} — still controlled by a private key. The delegate contract's code runs when the account is called, but the key holder can act at any time.`));
    } else {
      res.checks.push(check(
        'spender_type',
        'Spender type',
        spenderIsContract ? 'info' : 'warn',
        spenderIsContract
          ? `Spender is a contract (${spenderCode.codeBytes} bytes of code).`
          : 'Spender is an externally-owned account (EOA) — no code. An EOA can move approved funds at any time with no on-chain constraints.',
      ));
    }

    // Spender activity (weak signal, labelled honestly).
    let txCount = null;
    try {
      txCount = await getTxCount(spender);
      res.data.spender_tx_count = txCount;
      if (!spenderIsContract && txCount === 0) {
        res.checks.push(check('spender_activity', 'Spender activity', 'warn', 'This EOA has never sent a transaction (nonce 0). A never-used address is a weak signal only — it does not prove a scam, but it is unusual for a real protocol.'));
      } else {
        res.checks.push(check('spender_activity', 'Spender activity', 'info', `Spender has sent ${txCount} transaction(s).`));
      }
    } catch (_) { /* informational only */ }

    // Allowance size.
    if (allowance === 0n) {
      res.checks.push(check('allowance_size', 'Allowance size', 'pass', 'Allowance is 0 — the spender cannot move any tokens.'));
    } else if (isUnlimited) {
      res.checks.push(check('allowance_size', 'Allowance size', 'fail', 'UNLIMITED allowance (2^256 - 1). The spender could drain the entire token balance, now and in the future.'));
    } else {
      res.checks.push(check('allowance_size', 'Allowance size', 'info', `Allowance is ${res.data.allowance_human} — bounded, the spender can move at most this much.`));
    }

    // Verdict.
    if (allowance === 0n) {
      res.verdict = 'SAFE';
      res.summary = 'No allowance set — the spender cannot move any of these tokens.';
      res.reasons = ['Allowance is exactly 0.'];
    } else if (isUnlimited && !spenderIsContract) {
      res.verdict = 'DANGEROUS';
      res.summary = 'Unlimited allowance granted to an externally-owned account. That account can drain the full token balance at any time.';
      res.reasons = [
        'Allowance is unlimited (2^256 - 1).',
        'Spender is an EOA, not a contract — nothing on-chain constrains what it does with the approval.',
        'If this address is compromised or malicious, the entire balance is at risk.',
      ];
    } else if (isUnlimited) {
      res.verdict = 'RISKY';
      res.summary = 'Unlimited allowance granted to a contract. Only approve unlimited amounts to contracts you trust and whose code you have verified.';
      res.reasons = [
        'Allowance is unlimited (2^256 - 1).',
        'Spender is a contract — it can only act as its code allows, but the agent cannot verify the contract source without an Etherscan key.',
        'Consider revoking or lowering the allowance after use.',
      ];
    } else if (!spenderIsContract) {
      res.verdict = 'RISKY';
      res.summary = `Bounded allowance (${res.data.allowance_human}) granted to an EOA. The spender can move up to that amount.`;
      res.reasons = [
        `Allowance is bounded at ${res.data.allowance_human}.`,
        'Spender is an EOA — nothing on-chain constrains what it does with the approval.',
      ];
    } else {
      res.verdict = 'SAFE';
      res.summary = `Bounded allowance (${res.data.allowance_human}) granted to a contract. The spender can move at most that amount.`;
      res.reasons = [
        `Allowance is bounded at ${res.data.allowance_human}.`,
        'Spender is a contract — it can only act as its code allows.',
        'Still confirm the contract is the protocol you intended before signing.',
      ];
    }

    res.latency_ms = Date.now() - started;
    return { status: 200, body: res };
  } catch (e) {
    return { status: 502, body: { error: 'Could not read on-chain data.', detail: e.message, rpc_errors: e.details || undefined, hint: 'The public RPC may be down. Retry in a minute — the agent never fabricates allowances.' } };
  }
}

// --- transaction mode -------------------------------------------------------

async function guardTransaction(body) {
  const started = Date.now();
  const res = baseResult('transaction');
  const { to, data, value } = body;
  if (!isAddress(to)) {
    return { status: 400, body: { error: 'to must be a 0x address (40 hex chars).', hint: 'to is the contract the transaction calls.' } };
  }
  if (!isHexData(data) || data.length < 10) {
    return { status: 400, body: { error: 'data must be 0x hex calldata of at least 4 bytes (a function selector).', hint: 'Example approve calldata starts with 0x095ea7b3.' } };
  }
  let valueWei = 0n;
  if (value !== undefined && value !== null && value !== '') {
    try {
      valueWei = typeof value === 'string' && value.startsWith('0x')
        ? BigInt(value)
        : BigInt(String(value));
      if (valueWei < 0n) throw new Error('negative');
    } catch (_) {
      return { status: 400, body: { error: 'value must be a non-negative integer (wei, decimal or 0x hex).', hint: 'Most token calls carry value 0.' } };
    }
  }

  const selector = data.slice(0, 10).toLowerCase();
  const fn = SELECTORS[selector];
  const dataBuf = Buffer.from(data.slice(10), 'hex');
  let decoded = null;
  if (fn) {
    try { decoded = stringifyDecoded(decodeParams(fn.params, dataBuf)); } catch (_) { decoded = null; }
  }

  res.data = {
    to,
    selector,
    function: fn ? fn.name : null,
    decoded,
    value_wei: valueWei.toString(),
    value_eth: formatUnits(valueWei, 18),
  };

  try {
    const chainId = await getChainId();
    res.chain_id = chainId;
    if (chainId !== 1) {
      res.checks.push(check('chain', 'Chain id', 'warn', `RPC reports chain id ${chainId}, not Ethereum mainnet (1).`));
    }

    const target = await getCode(to);
    res.rpc_used = target.rpc;
    res.data.to_is_contract = target.isContract;
    res.data.to_code_bytes = target.codeBytes;
    res.data.to_kind = target.kind;
    if (target.kind === 'eoa') {
      res.checks.push(check('target_code', 'Target has code', 'fail', 'Target address has NO code — it is an EOA. A function call to an EOA does nothing on-chain; this is common in spoofed-token scams where the "token" is not a contract.'));
      res.verdict = 'DANGEROUS';
      res.summary = 'The transaction calls a function on an address with no code. It would do nothing on-chain — do not sign it.';
      res.reasons = [
        'Target is an EOA, not a contract.',
        'Calling a function selector on an EOA has no effect, yet the transaction still costs gas.',
        'Scam setups often show a fake token address that is just an EOA.',
      ];
      res.latency_ms = Date.now() - started;
      return { status: 200, body: res };
    }
    if (target.kind === 'eoa7702') {
      res.data.to_delegation_target = target.delegationTarget;
      res.checks.push(check('target_code', 'Target has code', 'warn', `Target is an EOA with an EIP-7702 delegation to ${target.delegationTarget}. The call executes the delegate contract's code — verify the delegate before signing.`));
    } else {
      res.checks.push(check('target_code', 'Target has code', 'pass', `Target is a contract (${target.codeBytes} bytes of code).`));
    }

    if (!fn) {
      res.checks.push(check('selector', 'Function recognised', 'warn', `Selector ${selector} is not in the agent's known list. The agent cannot tell what this call does — verify it on a block explorer before signing.`));
      res.verdict = 'UNKNOWN';
      res.summary = 'Unknown function selector — the agent cannot assess this transaction. Verify it manually before signing.';
      res.reasons = ['Selector is not a known ERC-20 / DeFi / NFT function in the local table.'];
      res.latency_ms = Date.now() - started;
      return { status: 200, body: res };
    }
    res.checks.push(check('selector', 'Function recognised', 'pass', `Call is ${fn.name}(${fn.params.map(([n, t]) => `${t} ${n}`).join(', ')}).`));

    if (valueWei > 0n) {
      res.checks.push(check('eth_value', 'ETH attached', 'warn', `${formatUnits(valueWei, 18)} ETH is attached. Most token functions are non-payable, so attached ETH would make the transaction revert — and if the function is payable, the ETH goes to the contract. Confirm this is intended.`));
    } else {
      res.checks.push(check('eth_value', 'ETH attached', 'pass', 'No ETH attached (value 0).'));
    }

    // Function-specific screening.
    const approvalFns = ['approve', 'increaseAllowance', 'permit'];
    if (approvalFns.includes(fn.name)) {
      const spender = decoded && decoded.spender;
      const amount = decoded && (decoded.amount ?? decoded.value ?? decoded.addedValue);
      const amountBig = amount !== undefined && amount !== null ? BigInt(amount) : null;
      const isUnlimited = amountBig === MAX_UINT256;
      let spenderIsContract = null;
      if (spender && isAddress(spender)) {
        const sc = await getCode(spender);
        spenderIsContract = sc.isContract;
        res.data.spender_is_contract = spenderIsContract;
        res.data.spender_code_bytes = sc.codeBytes;
        res.data.spender_kind = sc.kind;
        if (sc.kind === 'eoa7702') {
          res.data.spender_delegation_target = sc.delegationTarget;
          res.checks.push(check('spender_type', 'Spender type', 'warn',
            `Spender is an EOA with an EIP-7702 delegation to ${sc.delegationTarget} — still controlled by a private key.`));
        } else {
          res.checks.push(check('spender_type', 'Spender type', spenderIsContract ? 'info' : 'warn',
            spenderIsContract ? `Spender is a contract (${sc.codeBytes} bytes of code).` : 'Spender is an EOA — nothing on-chain constrains what it does with the approval.'));
        }
      }
      if (fn.name === 'permit') {
        res.checks.push(check('permit_note', 'Permit is signature-based', 'warn', 'permit() grants an allowance via an off-chain signature — no on-chain approve transaction is needed. A signed permit in the wrong hands is as powerful as the approval itself.'));
      }
      if (isUnlimited) {
        res.checks.push(check('approval_size', 'Approval size', 'fail', 'UNLIMITED approval (2^256 - 1).'));
        if (spenderIsContract === false) {
          res.verdict = 'DANGEROUS';
          res.summary = `Unlimited ${fn.name} to an EOA. That account could drain the full token balance.`;
          res.reasons = ['Approval amount is unlimited (2^256 - 1).', 'Spender is an EOA, not a contract.'];
        } else {
          res.verdict = 'RISKY';
          res.summary = `Unlimited ${fn.name} to a contract. Only approve unlimited amounts to contracts you trust.`;
          res.reasons = ['Approval amount is unlimited (2^256 - 1).', 'Spender is a contract — its code limits it, but the agent cannot verify the source.'];
        }
      } else if (amountBig !== null) {
        res.checks.push(check('approval_size', 'Approval size', 'info', `Approval amount is ${amountBig.toString()} raw units (bounded).`));
        if (spenderIsContract === false) {
          res.verdict = 'RISKY';
          res.summary = `Bounded ${fn.name} to an EOA. The spender can move up to the approved amount.`;
          res.reasons = [`Approval is bounded at ${amountBig.toString()} raw units.`, 'Spender is an EOA.'];
        } else {
          res.verdict = 'SAFE';
          res.summary = `Bounded ${fn.name} to a contract. The spender can move at most the approved amount.`;
          res.reasons = [`Approval is bounded at ${amountBig.toString()} raw units.`, 'Spender is a contract.'];
        }
      } else {
        res.verdict = 'UNKNOWN';
        res.summary = 'Could not decode the approval amount — the agent cannot assess this transaction.';
        res.reasons = ['Calldata decode failed for the amount field.'];
      }
    } else if (fn.name === 'setApprovalForAll') {
      const operator = decoded && decoded.operator;
      const approved = decoded && decoded.approved;
      let opIsContract = null;
      if (operator && isAddress(operator)) {
        const oc = await getCode(operator);
        opIsContract = oc.isContract;
        res.data.operator_is_contract = opIsContract;
        res.data.operator_kind = oc.kind;
        if (oc.kind === 'eoa7702') {
          res.data.operator_delegation_target = oc.delegationTarget;
          res.checks.push(check('operator_type', 'Operator type', 'warn',
            `Operator is an EOA with an EIP-7702 delegation to ${oc.delegationTarget} — still controlled by a private key.`));
        } else {
          res.checks.push(check('operator_type', 'Operator type', opIsContract ? 'info' : 'warn',
            opIsContract ? `Operator is a contract (${oc.codeBytes} bytes of code).` : 'Operator is an EOA.'));
        }
      }
      if (approved === true) {
        res.checks.push(check('approval_for_all', 'Approval for all', 'fail', 'setApprovalForAll(true) lets the operator move ALL of your NFTs in this collection.'));
        res.verdict = opIsContract === false ? 'DANGEROUS' : 'RISKY';
        res.summary = 'This grants an operator control over ALL of your NFTs in this collection. Only approve operators you fully trust (e.g. a marketplace you use).';
        res.reasons = ['setApprovalForAll(true) covers the entire collection, not one token.', opIsContract === false ? 'Operator is an EOA.' : 'Operator is a contract.'];
      } else {
        res.checks.push(check('approval_for_all', 'Approval for all', 'pass', 'setApprovalForAll(false) — this REVOKES the operator. Safe.'));
        res.verdict = 'SAFE';
        res.summary = 'This revokes an operator approval. Safe.';
        res.reasons = ['approved is false — the operator loses access.'];
      }
    } else if (fn.name === 'transfer' || fn.name === 'transferFrom' || fn.name === 'safeTransferFrom') {
      const recipient = decoded && (decoded.to || decoded.recipient);
      res.checks.push(check('transfer', 'Transfer screened', 'info', `Transfer of ${decoded && decoded.amount !== undefined ? decoded.amount : (decoded && decoded.tokenId !== undefined ? 'token ' + decoded.tokenId : 'unknown amount')} to ${recipient || 'unknown recipient'}. The agent cannot verify the recipient — double-check the address yourself.`));
      res.verdict = 'SAFE';
      res.summary = 'A plain transfer. The agent found no approval risk; still confirm the recipient address is the one you intended.';
      res.reasons = ['No approval or permission is granted by a transfer.', 'Risk is limited to sending to the wrong address.'];
    } else {
      res.checks.push(check('function', 'Function screened', 'info', `${fn.name} is a known function, but the agent has no specific risk rule for it. No approval is granted by this call type.`));
      res.verdict = 'SAFE';
      res.summary = `${fn.name} call — no approval or permission risk detected. Confirm the parameters are what you intended.`;
      res.reasons = [`${fn.name} does not grant token or NFT approvals.`];
    }

    res.latency_ms = Date.now() - started;
    return { status: 200, body: res };
  } catch (e) {
    return { status: 502, body: { error: 'Could not read on-chain data.', detail: e.message, rpc_errors: e.details || undefined, hint: 'The public RPC may be down. Retry in a minute — the agent never fabricates verdicts.' } };
  }
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

const DEMO_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogiGuard — Wallet &amp; Transaction Guard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#111}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:2rem}
label{display:block;margin:.5rem 0 .2rem;font-weight:600}
input,select{width:100%;padding:.5rem;font:inherit;box-sizing:border-box}
button{margin-top:.75rem;padding:.6rem 1.2rem;font:inherit;cursor:pointer}
pre{background:#f4f4f4;padding:1rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
.note{background:#fff8e1;border:1px solid #f0d98c;padding:.75rem 1rem}
code{background:#eee;padding:0 .25rem}
</style></head><body>
<h1>🛡️ LogiGuard — Wallet &amp; Transaction Guard</h1>
<p>Read-only guard for zkVerify Agent Games (Wildcard track). It screens ERC-20 approvals and
transactions <strong>before</strong> you sign them. It never signs anything, never sends transactions,
never touches private keys.</p>
<div class="note"><strong>What it cannot do:</strong> it cannot detect honeypots, cannot check Etherscan
verification (no API key by design), mainnet only, no price data. A verdict is a screen, not a guarantee.</div>

<h2>1. Check an allowance</h2>
<form id="allowanceForm">
<label>Token address <input name="token" value="0x6B175474E89094C44Da98b954EedeAC495271d0F"></label>
<label>Owner address <input name="owner" value="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"></label>
<label>Spender address <input name="spender" value="0x000000000022D473030F116dDEE9F6B43aC78BA3"></label>
<button type="submit">Check allowance</button>
</form>

<h2>2. Screen a transaction</h2>
<form id="txForm">
<label>To (contract called) <input name="to" value="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"></label>
<label>Calldata (0x…) <input name="data" value="0x095ea7b30000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"></label>
<label>Value in wei (0 for most token calls) <input name="value" value="0"></label>
<button type="submit">Screen transaction</button>
</form>

<h2>Result</h2>
<pre id="out">Fill a form and submit — or try the worked examples above (DAI allowance of vitalik.eth to Uniswap Permit2: unlimited, flagged RISKY; and an unlimited USDC approve to the Uniswap V2 router).</pre>
<script>
async function post(body){
  const out=document.getElementById('out'); out.textContent='Checking on-chain…';
  try{
    const r=await fetch('/guard',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    out.textContent=JSON.stringify(await r.json(),null,2);
  }catch(e){ out.textContent='Error: '+e.message; }
}
document.getElementById('allowanceForm').addEventListener('submit',e=>{
  e.preventDefault(); const f=new FormData(e.target);
  post({mode:'allowance',token:f.get('token').trim(),owner:f.get('owner').trim(),spender:f.get('spender').trim()});
});
document.getElementById('txForm').addEventListener('submit',e=>{
  e.preventDefault(); const f=new FormData(e.target);
  post({mode:'transaction',to:f.get('to').trim(),data:f.get('data').trim(),value:f.get('value').trim()});
});
</script>
<p><a href="/health">/health</a> · POST /guard with <code>{"mode":"allowance"|"transaction", ...}</code> ·
Source: see README.md</p>
</body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      let chainId = null;
      let rpcUsed = null;
      try {
        const c = await rpcCall('eth_chainId', []);
        chainId = Number(hexToBigInt(c.result));
        rpcUsed = c.rpc;
      } catch (_) { /* health stays ok; chain check is best-effort */ }
      return sendJson(res, 200, { ok: true, agent: 'LogiGuard', track: 'Wildcard', chain_id: chainId, rpc_used: rpcUsed, time: new Date().toISOString() });
    }
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(DEMO_HTML);
    }
    if (req.method === 'POST' && req.url === '/guard') {
      let raw;
      try { raw = await readBody(req); } catch (e) {
        return sendJson(res, 400, { error: e.message });
      }
      let body;
      try { body = JSON.parse(raw); } catch (_) {
        return sendJson(res, 400, { error: 'Body must be valid JSON.' });
      }
      if (!body || typeof body !== 'object') {
        return sendJson(res, 400, { error: 'Body must be a JSON object.' });
      }
      if (body.mode === 'allowance') {
        const r = await guardAllowance(body);
        return sendJson(res, r.status, r.body);
      }
      if (body.mode === 'transaction') {
        const r = await guardTransaction(body);
        return sendJson(res, r.status, r.body);
      }
      return sendJson(res, 400, { error: 'mode must be "allowance" or "transaction".' });
    }
    return sendJson(res, 404, { error: 'Not found. Use GET /health, GET /, or POST /guard.' });
  } catch (e) {
    return sendJson(res, 500, { error: 'Internal error.', detail: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`LogiGuard listening on http://localhost:${PORT} (POST /guard, GET /health)`);
  console.log(`RPC endpoints: ${RPCS.join(', ')}`);
});
