// ============================================================
// 文件：functions/api/apps.js
// 路由：/api/apps
// 作用：前台在线报名提交 / 后台报名名单管理
//   POST      -> 提交报名（公开）
//   GET       -> 报名列表（需管理令牌 x-token）
//   DELETE?id= -> 删除一条报名（需管理令牌 x-token）
// ============================================================
const HEADERS = {
  'content-type': 'application/json; charset=UTF-8',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type, x-token',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS'
};

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.MY_KV;

  if (request.method === 'OPTIONS') return new Response('ok', { headers: HEADERS });

  // 提交报名（公开，无需登录）
  if (request.method === 'POST') {
    const body = await request.json();
    if (!body.name || !body.phone) {
      return new Response(JSON.stringify({ error: '姓名与联系电话必填' }), { status: 400, headers: HEADERS });
    }
    const apps = (await kv.get('apps', 'json')) || [];
    apps.push({
      id: 'a' + Date.now() + Math.random().toString(36).slice(2, 6),
      name: body.name,
      major: body.major || '',
      dept: body.dept || '',
      deptName: body.deptName || '',
      phone: body.phone,
      bio: body.bio || '',
      time: new Date().toLocaleString('zh-CN')
    });
    await kv.put('apps', JSON.stringify(apps));
    return new Response(JSON.stringify({ ok: true }), { headers: HEADERS });
  }

  // 报名列表/删除仅超级管理员或办公室负责人
  const accounts = (await kv.get('accounts', 'json')) || {};
  const me = await whoAmI(kv, request.headers.get('x-token') || '', accounts);
  if (!me || (me.role !== 'super' && !(me.role === 'dept' && me.dept === 'office'))) {
    return new Response(JSON.stringify({ error: '无权限：报名管理仅超级管理员或办公室负责人可操作' }), { status: 403, headers: HEADERS });
  }

  // 报名列表
  if (request.method === 'GET') {
    const apps = (await kv.get('apps', 'json')) || [];
    return new Response(JSON.stringify(apps), { headers: HEADERS });
  }

  // 删除一条报名
  if (request.method === 'DELETE') {
    const id = new URL(request.url).searchParams.get('id');
    const apps = ((await kv.get('apps', 'json')) || []).filter(a => a.id !== id);
    await kv.put('apps', JSON.stringify(apps));
    return new Response(JSON.stringify({ ok: true }), { headers: HEADERS });
  }

  return new Response(JSON.stringify({ error: 'method not allowed' }), { status: 405, headers: HEADERS });
}

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 校验管理令牌并返回当前登录账号（sessions 有效期 24 小时）
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
