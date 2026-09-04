#!/usr/bin/env node
/**
 * cti-aggregator-mcp stdio client · 银狐检测专用
 * 版本: V1.0（2026-09-04）
 *
 * 通过 JSON-RPC 2.0 over stdin/stdout 与 cti-aggregator-mcp 进程通信，
 * 调 investigate_domain 工具拿结构化报告，提取关键字段供 ScoringEngine 使用。
 *
 * 通信流程（符合 MCP 协议 2024-11-05）：
 *   1. initialize              握手（clientInfo + protocolVersion）
 *   2. notifications/initialized 通知
 *   3. tools/call investigate_domain 拿 markdown 报告
 *   4. 解析字段 → {creationDays, registrationDate, registrar, nameServers, icpStatus}
 *
 * 失败/超时返回 null，不抛异常（避免阻断 detect.js 主流程，由调用方降级到 RDAP）。
 */

const { spawn } = require('child_process');

const DEFAULT_CMD = 'cti-aggregator-mcp'; // pyproject.toml scripts 入口
const PROTOCOL_VERSION = '2024-11-05';
const DEFAULT_TIMEOUT_MS = 30000;

/**
 * 调 MCP 的 investigate_domain 工具
 *
 * @param {string} domain 域名（裸域，不带协议）
 * @param {object} [opts] { cmd, cwd, timeout }
 * @returns {Promise<{creationDays?, registrationDate?, registrar?, nameServers?, icpStatus?} | null>}
 */
async function investigateDomain(domain, opts = {}) {
  const cmd = opts.cmd || DEFAULT_CMD;
  const cwd = opts.cwd || process.cwd();
  const timeoutMs = opts.timeout || DEFAULT_TIMEOUT_MS;

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, [], { cwd, env: process.env, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (e) {
      process.stderr.write(`[mcp-client] 启动进程失败: ${e.message}\n`);
      resolve(null);
      return;
    }

    let buf = '';
    let reqId = 1;
    const inflight = new Map();
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      process.stderr.write(`[mcp-client] 调用超时 (${timeoutMs}ms)\n`);
      resolve(null);
    }, timeoutMs);

    child.stdout.on('data', chunk => {
      buf += chunk.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          if (typeof msg.id === 'number' && inflight.has(msg.id)) {
            inflight.get(msg.id)(msg);
            inflight.delete(msg.id);
          }
        } catch (e) { /* 忽略非 JSON 行 */ }
      }
    });

    child.stderr.on('data', d => {
      // MCP server 偶尔在 stderr 写日志，保留供调试
      process.stderr.write(`[mcp-stderr] ${d}`);
    });

    child.on('error', e => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.stderr.write(`[mcp-client] 进程错误: ${e.message}\n`);
      resolve(null);
    });

    child.on('exit', code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (inflight.size > 0) {
        process.stderr.write(`[mcp-client] 进程退出但还有未响应请求 (exit=${code})\n`);
        resolve(null);
      }
    });

    function send(method, params) {
      return new Promise(res => {
        const id = reqId++;
        inflight.set(id, res);
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      });
    }

    (async () => {
      try {
        // 1. initialize 握手
        await send('initialize', {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: 'silver-fox-detector', version: '1.2' },
        });
        // 2. initialized 通知（无 id，服务端需要这个以进入 ready 状态）
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
        // 3. 调工具
        const resp = await send('tools/call', {
          name: 'investigate_domain',
          arguments: { domain },
        });
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill();
        // 4. 解析
        const text = resp?.result?.content?.[0]?.text || '';
        resolve(parseReport(text));
      } catch (e) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill();
        process.stderr.write(`[mcp-client] JSON-RPC 失败: ${e.message}\n`);
        resolve(null);
      }
    })();
  });
}

/**
 * 从 MCP markdown 报告提取关键字段（兼容 cti-aggregator-mcp 当前输出格式）
 *
 * 报告片段示例：
 *   - **注册商**: MarkMonitor Inc.
 *   - **注册组织**: Example Corp
 *   - **注册时间**: 2005-01-15
 *   - **域名年龄**: 7902 天
 *   - **DNS 服务器**: ns1.example.com, ns2.example.com
 *   - **ICP 备案**: 已备案
 */
function parseReport(md) {
  if (!md || typeof md !== 'string') return null;
  const out = {};
  const daysMatch = md.match(/- \*\*域名年龄\*\*:\s*(\d+)\s*天/);
  if (daysMatch) out.creationDays = parseInt(daysMatch[1], 10);
  const regMatch = md.match(/- \*\*注册时间\*\*:\s*(\d{4}-\d{2}-\d{2})/);
  if (regMatch) out.registrationDate = regMatch[1];
  const rMatch = md.match(/- \*\*注册商\*\*:\s*(.+)/);
  if (rMatch) out.registrar = rMatch[1].trim();
  const nsMatch = md.match(/- \*\*DNS 服务器\*\*:\s*(.+)/);
  if (nsMatch) {
    out.nameServers = nsMatch[1].split(',').map(s => s.trim()).filter(Boolean);
  }
  const icpMatch = md.match(/- \*\*ICP 备案\*\*:\s*(.+)/);
  if (icpMatch) out.icpStatus = icpMatch[1].trim();
  return Object.keys(out).length > 0 ? out : null;
}

module.exports = { investigateDomain, parseReport, PROTOCOL_VERSION };