/**
 * LogiGuard test script — runs the server and exercises POST /guard against
 * REAL Ethereum mainnet state via public RPCs. Nothing is faked: every
 * allowance, code check and verdict comes from a live RPC response.
 *
 * Usage: node test-guard.js
 * Exits 0 when health + at least one allowance check + one transaction
 * decode succeed; exits 1 otherwise.
 */
'use strict';

const { spawn } = require('child_process');
const http = require('http');

const PORT = 3001;
const BASE = `http://localhost:${PORT}`;

function post(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(BASE + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) },
    }, (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; });
      res.on('end', () => { try { resolve({ status: res.statusCode, json: JSON.parse(buf) }); } catch (e) { resolve({ status: res.statusCode, raw: buf }); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function get(path) {
  return new Promise((resolve, reject) => {
    http.get(BASE + path, (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: buf }));
    }).on('error', reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- calldata builders (deterministic ABI encoding) ---
const padAddr = (a) => a.slice(2).toLowerCase().padStart(64, '0');
const padUint = (n) => BigInt(n).toString(16).padStart(64, '0');
const MAX = (1n << 256n) - 1n;

const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const DAI = '0x6B175474E89094C44Da98b954EedeAC495271d0F';
const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const V2_ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const V3_ROUTER = '0xE592427A0AEce92De3Edee1F18E0157C05861564'; // Uniswap V3 SwapRouter
const ONEINCH = '0x1111111254EEB25477B68fb85Ed929f73A960582';
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3'; // Uniswap Permit2
const CRYPTOKITTIES = '0x06012c8cf97BEaD5deAe237070F9587f8E7A266d';

async function main() {
  const server = spawn('node', ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d; });
  server.stderr.on('data', (d) => { serverLog += d; });

  const results = [];
  const note = (name, ok, detail) => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  };

  try {
    // Wait for health.
    let healthy = false;
    for (let i = 0; i < 30; i++) {
      try {
        const h = await get('/health');
        if (h.status === 200) { healthy = true; break; }
      } catch (_) { /* not up yet */ }
      await sleep(500);
    }
    note('GET /health', healthy, healthy ? 'server up' : 'server did not start');
    if (!healthy) { console.log(serverLog); process.exitCode = 1; return; }

    const h = await get('/health');
    const hj = JSON.parse(h.body);
    console.log(`      health: chain_id=${hj.chain_id} rpc=${hj.rpc_used}`);

    const home = await get('/');
    note('GET / demo page', home.status === 200 && home.body.includes('LogiGuard'), `status ${home.status}, ${home.body.length} bytes`);

    // --- Allowance probes: real mainnet state ---
    console.log('\n--- Allowance mode (live mainnet) ---');
    const allowanceCases = [
      ['USDC / vitalik -> V2 router', USDC, VITALIK, V2_ROUTER],
      ['DAI / vitalik -> V2 router', DAI, VITALIK, V2_ROUTER],
      ['USDT / vitalik -> V2 router', USDT, VITALIK, V2_ROUTER],
      ['WETH / vitalik -> V2 router', WETH, VITALIK, V2_ROUTER],
      ['USDC / vitalik -> V3 router', USDC, VITALIK, V3_ROUTER],
      ['USDC / vitalik -> 1inch router', USDC, VITALIK, ONEINCH],
      ['DAI / vitalik -> Permit2 (UNLIMITED)', DAI, VITALIK, PERMIT2],
    ];
    let allowanceOk = 0;
    let permit2Risky = false;
    for (const [name, token, owner, spender] of allowanceCases) {
      const t0 = Date.now();
      const r = await post('/guard', { mode: 'allowance', token, owner, spender });
      const ms = Date.now() - t0;
      if (r.status === 200) {
        allowanceOk++;
        const j = r.json;
        console.log(`  ${name}: verdict=${j.verdict} allowance=${j.data.allowance_human} (raw ${j.data.allowance}) unlimited=${j.data.is_unlimited} spender_contract=${j.data.spender_is_contract} spender_kind=${j.data.spender_kind} rpc=${j.rpc_used} ${ms}ms`);
        if (spender === PERMIT2 && j.verdict === 'RISKY' && j.data.is_unlimited === true) permit2Risky = true;
      } else {
        console.log(`  ${name}: HTTP ${r.status} — ${JSON.stringify(r.json)}`);
      }
    }
    note('Allowance checks (live RPC)', allowanceOk > 0, `${allowanceOk}/${allowanceCases.length} returned live verdicts`);
    note('DAI/vitalik/Permit2 unlimited -> RISKY', permit2Risky, 'real unlimited allowance flagged RISKY');

    // --- Transaction mode: real calldata decodes ---
    console.log('\n--- Transaction mode (calldata decode) ---');
    const txCases = [
      ['approve UNLIMITED to V2 router (USDC)', { to: USDC, data: '0x095ea7b3' + padAddr(V2_ROUTER) + padUint(MAX), value: '0' }, 'RISKY'],
      ['approve 100 USDC to V2 router', { to: USDC, data: '0x095ea7b3' + padAddr(V2_ROUTER) + padUint(100_000_000n), value: '0' }, 'SAFE'],
      ['approve UNLIMITED to EOA (vitalik)', { to: USDC, data: '0x095ea7b3' + padAddr(VITALIK) + padUint(MAX), value: '0' }, 'DANGEROUS'],
      ['transfer 1 USDC to vitalik', { to: USDC, data: '0xa9059cbb' + padAddr(VITALIK) + padUint(1_000_000n), value: '0' }, 'SAFE'],
      ['setApprovalForAll(true) to EOA', { to: CRYPTOKITTIES, data: '0xa22cb465' + padAddr(VITALIK) + padUint(1n), value: '0' }, 'DANGEROUS'],
      ['permit UNLIMITED to V2 router', { to: USDC, data: '0xd505accf' + padAddr(VITALIK) + padAddr(V2_ROUTER) + padUint(MAX) + padUint(1790000000n) + padUint(27n) + '00'.repeat(32) + '00'.repeat(32), value: '0' }, null],
      ['unknown selector 0xdeadbeef', { to: USDC, data: '0xdeadbeef' + '00'.repeat(32), value: '0' }, 'UNKNOWN'],
      ['approve calldata to 7702 EOA target', { to: VITALIK, data: '0x095ea7b3' + padAddr(V2_ROUTER) + padUint(MAX), value: '0' }, 'RISKY'],
      ['approve with 1 ETH attached', { to: USDC, data: '0x095ea7b3' + padAddr(V2_ROUTER) + padUint(1000n), value: '1000000000000000000' }, null],
    ];
    let txOk = 0;
    for (const [name, body, expected] of txCases) {
      const t0 = Date.now();
      const r = await post('/guard', { mode: 'transaction', ...body });
      const ms = Date.now() - t0;
      if (r.status === 200) {
        const j = r.json;
        const match = expected === null ? '(no fixed expectation)' : (j.verdict === expected ? 'as expected' : `MISMATCH: expected ${expected}`);
        if (expected === null || j.verdict === expected) txOk++;
        console.log(`  ${name}: verdict=${j.verdict} fn=${j.data.function} ${match} — ${j.summary} (${ms}ms)`);
        if (j.data.decoded) console.log(`      decoded: ${JSON.stringify(j.data.decoded)}`);
      } else {
        console.log(`  ${name}: HTTP ${r.status} — ${JSON.stringify(r.json)}`);
      }
    }
    note('Transaction decodes', txOk === txCases.length, `${txOk}/${txCases.length} matched expectations`);

    // --- Input validation ---
    console.log('\n--- Input validation ---');
    const bad1 = await post('/guard', { mode: 'allowance', token: 'not-an-address', owner: VITALIK, spender: V2_ROUTER });
    note('Bad address -> 400', bad1.status === 400, `status ${bad1.status}`);
    const bad2 = await post('/guard', { mode: 'nonsense' });
    note('Bad mode -> 400', bad2.status === 400, `status ${bad2.status}`);
    const bad3 = await post('/guard', { mode: 'transaction', to: USDC, data: '0x1234' });
    note('Short calldata -> 400', bad3.status === 400, `status ${bad3.status}`);
  } finally {
    server.kill();
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  if (failed.length) { process.exitCode = 1; console.log('Failures:', failed.map((f) => f.name).join(', ')); }
}

main().catch((e) => { console.error('Test harness error:', e); process.exit(1); });
