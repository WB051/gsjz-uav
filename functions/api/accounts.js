// ============================================================
// 文件：functions/api/accounts.js
// 路由：/api/accounts
// 作用：后台账号管理（仅超级管理员）
//   GET             -> 账号列表（不含密码哈希）
//   POST action=add     -> 新增账号 { user, pwd, name, role, dept }
//   POST action=update  -> 修改账号 { user, pwd?, name, role, dept }
//   POST action=delete  -> 删除账号 { user }
// 说明：密码以 SHA-256 哈希存于 KV 的 accounts 键下；仅超级管理员
//       可管理账号（校验登录令牌 -> 会话 -> 账号角色）。
// ============================================================
const HEADERS = {
  'content-type': 'application/json; charset=UTF-8',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type, x-token',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};
const VALID_ROLES = ['super', 'dept'];
const VALID_DEPTS = ['chair', 'tech', 'media', 'office', 'external'];

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.MY_KV;

  if (request.method === 'OPTIONS') return new Response('ok', { headers: HEADERS });

  // 仅超级管理员可管理账号
  const accounts = (await kv.get('accounts', 'json')) || {};
  const token = request.headers.get('x-token') || '';
  const me = await whoAmI(kv, token, accounts);
  if (!me || me.role !== 'super') {
    return new Response(JSON.stringify({ error: '无权限：仅超级管理员可管理账号' }), { status: 403, headers: HEADERS });
  }

  // 账号列表
  if (request.method === 'GET') {
    const list = {};
    for (const u in accounts) list[u] = { name: accounts[u].name, role: accounts[u].role, dept: accounts[u].dept || null };
    return new Response(JSON.stringify(list), { headers: HEADERS });
  }

  // 增 / 改 / 删
  if (request.method === 'POST') {
    const body = await request.json();
    const action = body.action;
    const user = (body.user || '').trim();
    const name = (body.name || '').trim();
    const role = body.role;
    const dept = role === 'dept' ? body.dept : null;

    if (action === 'add') {
      if (!user || !name || !role) return bad('用户名、姓名、角色必填');
      if (!VALID_ROLES.includes(role)) return bad('角色不合法');
      if (role === 'dept' && !VALID_DEPTS.includes(dept)) return bad('部门不合法');
      if (accounts[user]) return bad('用户名已存在');
      if (!body.pwd || body.pwd.length < 6) return bad('密码至少6位');
      accounts[user] = { pwdHash: await sha256(body.pwd), name: name, role: role, dept: dept };
      await kv.put('accounts', JSON.stringify(accounts));
      return ok();
    }

    if (action === 'update') {
      if (!accounts[user]) return bad('账号不存在');
      if (!name || !role) return bad('姓名、角色必填');
      if (!VALID_ROLES.includes(role)) return bad('角色不合法');
      if (role === 'dept' && !VALID_DEPTS.includes(dept)) return bad('部门不合法');
      accounts[user].name = name;
      accounts[user].role = role;
      accounts[user].dept = dept;
      if (body.pwd) {
        if (body.pwd.length < 6) return bad('密码至少6位');
        accounts[user].pwdHash = await sha256(body.pwd);
      }
      await kv.put('accounts', JSON.stringify(accounts));
      return ok();
    }

    if (action === 'delete') {
      if (user === 'admin') return bad('超级管理员账号不可删除');
      if (!accounts[user]) return bad('账号不存在');
      delete accounts[user];
      await kv.put('accounts', JSON.stringify(accounts));
      return ok();
    }

    return bad('未知操作');
  }

  return new Response(JSON.stringify({ error: 'method not allowed' }), { status: 405, headers: HEADERS });
}

function bad(msg) { return new Response(JSON.stringify({ error: msg }), { status: 400, headers: HEADERS }); }
function ok() { return new Response(JSON.stringify({ ok: true }), { headers: HEADERS }); }

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 通过令牌取当前登录账号（sessions 有效期 24 小时）
async function whoAmI(kv, token, accounts) {
  if (!token) return null;
  const sessions = (await kv.get('sessions', 'json')) || {};
  const s = sessions[token];
  if (!s) return null;
  if (s.exp < Date.now()) {
    delete sessions[token];
    await kv.put('sessions', JSON.stringify(sessions));
    return null;
  }
  return accounts[s.user] || null;
}
