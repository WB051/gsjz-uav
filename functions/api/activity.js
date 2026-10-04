// ============================================================
// 文件：functions/api/activity.js
// 路由：/api/activity
// 作用：活动预告 / 活动回顾的发布、编辑与删除（后台用）
//   POST -> 仅更新 site_data 中的 events 与 reviews 字段，其余字段保持不变
// 权限：仅超级管理员 或 宣传部(media)负责人可操作（带 x-token）
// 说明：前台读取活动仍走公开的 /api/content；本接口专供后台活动管理保存。
// ============================================================
const HEADERS = {
  'content-type': 'application/json; charset=UTF-8',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type, x-token',
  'Access-Control-Allow-Methods': 'POST, OPTIONS'
};

export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.MY_KV;

  if (request.method === 'OPTIONS') return new Response('ok', { headers: HEADERS });
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method not allowed' }), { status: 405, headers: HEADERS });
  }

  // 仅超级管理员或宣传部(media)负责人
  const accounts = (await kv.get('accounts', 'json')) || {};
  const me = await whoAmI(kv, request.headers.get('x-token') || '', accounts);
  if (!me || (me.role !== 'super' && !(me.role === 'dept' && me.dept === 'media'))) {
    return new Response(JSON.stringify({ error: '无权限：活动发布仅超级管理员或宣传部负责人可操作' }), { status: 403, headers: HEADERS });
  }

  const body = await request.json();
  const data = (await kv.get('site_data', 'json')) || {};
  // 只合并活动相关字段，避免越权改写简介/部门/荣誉等其他内容
  if (Array.isArray(body.events)) data.events = body.events;
  if (Array.isArray(body.reviews)) data.reviews = body.reviews;
  await kv.put('site_data', JSON.stringify(data));
  return new Response(JSON.stringify({ ok: true }), { headers: HEADERS });
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
