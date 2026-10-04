// ============================================================
// 文件：functions/api/content.js
// 路由：/api/content
// 作用：网站内容（协会简介/部门/活动/回顾/荣誉等）的读写接口
//   GET  -> 返回内容 JSON（公开读，访客加载页面用）
//   POST -> 更新内容（需管理令牌 x-token，管理后台用）
// 说明：数据存放在 Cloudflare KV（绑定到本项目的变量名是 MY_KV）
// ============================================================
const HEADERS = {
  'content-type': 'application/json; charset=UTF-8',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type, x-token',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.MY_KV;

  if (request.method === 'OPTIONS') return new Response('ok', { headers: HEADERS });

  // 读取内容（公开）
  if (request.method === 'GET') {
    const data = (await kv.get('site_data', 'json')) || {};
    return new Response(JSON.stringify(data), { headers: HEADERS });
  }

  // 更新内容（需管理令牌）
  if (request.method === 'POST') {
    if (!(await isAdmin(kv, request.headers.get('x-token') || ''))) {
      return new Response(JSON.stringify({ error: '无权限' }), { status: 403, headers: HEADERS });
    }
    const body = await request.json();
    await kv.put('site_data', JSON.stringify(body));
    return new Response(JSON.stringify({ ok: true }), { headers: HEADERS });
  }

  return new Response(JSON.stringify({ error: 'method not allowed' }), { status: 405, headers: HEADERS });
}

// SHA-256 摘要（WebCrypto，边缘运行时可用）
async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 校验管理令牌（登录时写入 sessions，有效期 24 小时）
async function isAdmin(kv, token) {
  if (!token) return false;
  const sessions = (await kv.get('sessions', 'json')) || {};
  const s = sessions[token];
  if (!s) return false;
  if (s.exp < Date.now()) {
    delete sessions[token];
    await kv.put('sessions', JSON.stringify(sessions));
    return false;
  }
  return true;
}
