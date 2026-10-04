// ============================================================
// 文件：functions/api/login.js
// 路由：/api/login
// 作用：账号密码登录，返回管理令牌与角色
//  POST {user, pwd} -> { token, role, name, dept }
// 说明：账号存在 KV 的 accounts 键下（密码存 SHA-256 哈希），
//       登录成功写入 sessions 键（有效期 24 小时）
// ============================================================
const HEADERS = {
  'content-type': 'application/json; charset=UTF-8',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS'
};

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.MY_KV;

  if (request.method === 'OPTIONS') return new Response('ok', { headers: HEADERS });
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method not allowed' }), { status: 405, headers: HEADERS });
  }

  const { user, pwd } = await request.json();
  if (!user || !pwd) {
    return new Response(JSON.stringify({ error: '请输入账号和密码' }), { status: 400, headers: HEADERS });
  }

  const accounts = (await kv.get('accounts', 'json')) || {};
  const a = accounts[user];
  if (!a) return new Response(JSON.stringify({ error: '账号不存在' }), { status: 401, headers: HEADERS });

  if ((await sha256(pwd)) !== a.pwdHash) {
    return new Response(JSON.stringify({ error: '密码错误' }), { status: 401, headers: HEADERS });
  }

  // 签发 24 小时令牌
  const token = await sha256(user + Date.now() + Math.random());
  const sessions = (await kv.get('sessions', 'json')) || {};
  sessions[token] = { user, exp: Date.now() + 86400000 };
  await kv.put('sessions', JSON.stringify(sessions));

  return new Response(
    JSON.stringify({ token, role: a.role, name: a.name, dept: a.dept || null }),
    { headers: HEADERS }
  );
}

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
