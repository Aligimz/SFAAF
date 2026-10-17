const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
const required = ['DATABASE_URL', 'JWT_SECRET', 'SETUP_KEY'];
for (const key of required) if (!process.env[key]) { console.error(`Missing required environment variable: ${key}`); process.exit(1); }
if (process.env.JWT_SECRET.length < 32 || process.env.SETUP_KEY.length < 24) { console.error('JWT_SECRET must be 32+ chars and SETUP_KEY 24+ chars.'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: isProd ? { rejectUnauthorized: false } : undefined });
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY, username VARCHAR(80) UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    display_name VARCHAR(120) NOT NULL, role VARCHAR(30) NOT NULL DEFAULT 'staff', active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS sectors (
    id BIGSERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, description TEXT DEFAULT '', manager_name VARCHAR(120) DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS staff (
    id BIGSERIAL PRIMARY KEY, full_name VARCHAR(120) NOT NULL, character_name VARCHAR(120) DEFAULT '', discord_username VARCHAR(100) DEFAULT '',
    discord_id VARCHAR(40) DEFAULT '', fivem_id VARCHAR(100) DEFAULT '', rank_name VARCHAR(120) DEFAULT '', sector_id BIGINT REFERENCES sectors(id) ON DELETE SET NULL,
    supervisor VARCHAR(120) DEFAULT '', status VARCHAR(30) NOT NULL DEFAULT 'active', notes TEXT DEFAULT '', joined_at DATE DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS tasks (
    id BIGSERIAL PRIMARY KEY, title VARCHAR(180) NOT NULL, description TEXT DEFAULT '', assignee VARCHAR(120) DEFAULT '', sector_id BIGINT REFERENCES sectors(id) ON DELETE SET NULL,
    priority VARCHAR(20) NOT NULL DEFAULT 'normal', status VARCHAR(30) NOT NULL DEFAULT 'new', due_date DATE, created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS shifts (
    id BIGSERIAL PRIMARY KEY, staff_id BIGINT REFERENCES staff(id) ON DELETE SET NULL, staff_name VARCHAR(120) NOT NULL,
    shift_date DATE NOT NULL DEFAULT CURRENT_DATE, start_time VARCHAR(10) DEFAULT '', end_time VARCHAR(10) DEFAULT '',
    status VARCHAR(30) NOT NULL DEFAULT 'scheduled', notes TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS gangs (
    id BIGSERIAL PRIMARY KEY, name VARCHAR(120) UNIQUE NOT NULL, leader VARCHAR(120) DEFAULT '', deputy VARCHAR(120) DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0, status VARCHAR(30) NOT NULL DEFAULT 'active', notes TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS complaints (
    id BIGSERIAL PRIMARY KEY, reference VARCHAR(30) UNIQUE NOT NULL, title VARCHAR(180) NOT NULL, category VARCHAR(80) DEFAULT 'general',
    subject_name VARCHAR(120) DEFAULT '', assigned_to VARCHAR(120) DEFAULT '', status VARCHAR(30) NOT NULL DEFAULT 'new', details TEXT DEFAULT '',
    decision TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE SET NULL, username VARCHAR(80) DEFAULT '',
    action VARCHAR(100) NOT NULL, entity VARCHAR(80) NOT NULL, entity_id VARCHAR(80) DEFAULT '', details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`);
}
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
function auth(req, res, next) {
  const token = req.cookies.elite_session || (req.headers.authorization || '').replace(/^Bearer /, '');
  if (!token) return res.status(401).json({ error: 'يلزم تسجيل الدخول.' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.clearCookie('elite_session'); return res.status(401).json({ error: 'انتهت الجلسة، سجل الدخول مجدداً.' }); }
}
const ownerOnly = (req, res, next) => req.user?.role === 'owner' ? next() : res.status(403).json({ error: 'هذه العملية متاحة للمالك فقط.' });
const managerOrOwner = (req, res, next) => ['owner','manager'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'لا تملك صلاحية تنفيذ هذه العملية.' });
async function audit(req, action, entity, entityId = '', details = {}) {
  await pool.query('INSERT INTO audit_logs(user_id,username,action,entity,entity_id,details) VALUES($1,$2,$3,$4,$5,$6)', [req.user?.id || null, req.user?.username || 'system', action, entity, String(entityId), JSON.stringify(details)]);
}
app.get('/api/health', asyncRoute(async (_req,res) => { await pool.query('SELECT 1'); res.json({ status:'ok', database:'connected' }); }));
app.get('/api/setup/status', asyncRoute(async (_req,res) => { const r = await pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role='owner'"); res.json({ setupRequired: r.rows[0].count === 0 }); }));
app.post('/api/setup/owner', asyncRoute(async (req,res) => {
  const count = await pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role='owner'");
  if (count.rows[0].count > 0) return res.status(409).json({ error:'تم إعداد حساب المالك مسبقاً.' });
  const { setupKey, username, password, displayName } = req.body;
  if (setupKey !== process.env.SETUP_KEY) return res.status(403).json({ error:'مفتاح الإعداد غير صحيح.' });
  if (!/^[a-zA-Z0-9_.-]{3,40}$/.test(username || '') || !password || password.length < 12 || password.length > 200 || !displayName?.trim()) return res.status(400).json({ error:'أدخل اسم مستخدم صحيحاً وكلمة مرور لا تقل عن 12 حرفاً والاسم الظاهر.' });
  const hash = await bcrypt.hash(password, 12);
  const r = await pool.query('INSERT INTO users(username,password_hash,display_name,role) VALUES($1,$2,$3,\'owner\') RETURNING id,username,display_name,role', [username,hash,displayName.trim()]);
  res.status(201).json({ message:'تم إنشاء حساب المالك. يمكنك تسجيل الدخول الآن.', user:r.rows[0] });
}));
app.post('/api/auth/login', asyncRoute(async (req,res) => {
  const { username,password } = req.body;
  const r = await pool.query('SELECT * FROM users WHERE username=$1 AND active=TRUE', [username || '']);
  if (!r.rows[0] || !(await bcrypt.compare(password || '', r.rows[0].password_hash))) return res.status(401).json({ error:'اسم المستخدم أو كلمة المرور غير صحيحة.' });
  const u = r.rows[0], token = jwt.sign({ id:u.id, username:u.username, displayName:u.display_name, role:u.role }, process.env.JWT_SECRET, { expiresIn:'8h' });
  res.cookie('elite_session', token, { httpOnly:true, secure:isProd, sameSite:'strict', maxAge:8*60*60*1000, path:'/' });
  req.user = { id:u.id, username:u.username, role:u.role }; await audit(req,'login','user',u.id);
  res.json({ user:{ id:u.id, username:u.username, displayName:u.display_name, role:u.role } });
}));
app.post('/api/auth/logout', (req,res) => { res.clearCookie('elite_session', { httpOnly:true, secure:isProd, sameSite:'strict', path:'/' }); res.json({ ok:true }); });
app.get('/api/auth/me', auth, asyncRoute(async (req,res) => { const r=await pool.query('SELECT id,username,display_name,role,active FROM users WHERE id=$1',[req.user.id]); if(!r.rows[0]||!r.rows[0].active) return res.status(401).json({error:'الحساب غير فعال'}); res.json({user:r.rows[0]}); }));
app.get('/api/overview', auth, asyncRoute(async (_req,res) => {
  const queries = await Promise.all([
    pool.query('SELECT COUNT(*)::int n FROM staff WHERE status=\'active\''), pool.query('SELECT COUNT(*)::int n FROM sectors WHERE status=\'active\''),
    pool.query("SELECT COUNT(*)::int n FROM tasks WHERE status NOT IN ('completed','cancelled')"), pool.query("SELECT COUNT(*)::int n FROM complaints WHERE status NOT IN ('closed','rejected')"),
    pool.query('SELECT id,full_name,rank_name,sector_id,status,created_at FROM staff ORDER BY created_at DESC LIMIT 6'),
    pool.query('SELECT id,title,status,priority,due_date FROM tasks ORDER BY created_at DESC LIMIT 6'),
    pool.query('SELECT id,username,action,entity,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 8')
  ]);
  res.json({ stats:{staff:queries[0].rows[0].n,sectors:queries[1].rows[0].n,tasks:queries[2].rows[0].n,complaints:queries[3].rows[0].n}, recentStaff:queries[4].rows, recentTasks:queries[5].rows, activity:queries[6].rows });
}));
const resources = {
  staff: { table:'staff', fields:['full_name','character_name','discord_username','discord_id','fivem_id','rank_name','sector_id','supervisor','status','notes','joined_at'], required:['full_name'], searchable:['full_name','character_name','discord_username','discord_id','rank_name','supervisor','status'] },
  sectors: { table:'sectors', fields:['name','description','manager_name','status'], required:['name'], searchable:['name','description','manager_name','status'] },
  tasks: { table:'tasks', fields:['title','description','assignee','sector_id','priority','status','due_date'], required:['title'], searchable:['title','assignee','priority','status'] },
  shifts: { table:'shifts', fields:['staff_id','staff_name','shift_date','start_time','end_time','status','notes'], required:['staff_name','shift_date'], searchable:['staff_name','status','shift_date'] },
  gangs: { table:'gangs', fields:['name','leader','deputy','member_count','status','notes'], required:['name'], searchable:['name','leader','deputy','status'] },
  complaints: { table:'complaints', fields:['title','category','subject_name','assigned_to','status','details','decision'], required:['title'], searchable:['reference','title','category','subject_name','assigned_to','status'] }
};
function validResource(req,res,next) { if (['users','audit'].includes(req.params.resource)) return next('route'); req.resource=resources[req.params.resource]; if(!req.resource) return res.status(404).json({error:'القسم غير موجود.'}); next(); }
app.get('/api/:resource', auth, validResource, asyncRoute(async (req,res) => {
  const {table,fields,searchable}=req.resource; const limit=Math.min(Math.max(parseInt(req.query.limit)||100,1),300); const q=(req.query.q||'').trim();
  let sql=`SELECT * FROM ${table}`, params=[];
  if(q){ params=[`%${q}%`]; sql += ' WHERE ('+searchable.map(f=>`CAST(${f} AS TEXT) ILIKE $1`).join(' OR ')+')'; }
  sql += ` ORDER BY created_at DESC LIMIT ${limit}`; const r=await pool.query(sql,params); res.json({items:r.rows,fields});
}));
app.post('/api/:resource', auth, managerOrOwner, validResource, asyncRoute(async (req,res) => {
  const {table,fields,required}=req.resource; const data=req.body||{};
  for(const f of required) if(data[f]===undefined || String(data[f]).trim()==='') return res.status(400).json({error:`الحقل ${f} مطلوب.`});
  const keys=fields.filter(f=>Object.hasOwn(data,f)); const vals=keys.map(f=>data[f]=== '' ? null : data[f]);
  if(table==='tasks') { keys.push('created_by'); vals.push(req.user.id); }
  if(table==='complaints') { keys.push('reference'); vals.push('CMP-'+Date.now().toString(36).toUpperCase()); }
  if(!keys.length) return res.status(400).json({error:'لا توجد بيانات للحفظ.'});
  const sql=`INSERT INTO ${table} (${keys.join(',')}) VALUES (${keys.map((_,i)=>`$${i+1}`).join(',')}) RETURNING *`; const r=await pool.query(sql,vals); await audit(req,'create',table,r.rows[0].id,r.rows[0]); res.status(201).json({item:r.rows[0]});
}));
app.patch('/api/:resource/:id', auth, managerOrOwner, validResource, asyncRoute(async (req,res) => {
  const {table,fields}=req.resource; const keys=fields.filter(f=>Object.hasOwn(req.body||{},f)); if(!keys.length) return res.status(400).json({error:'لا توجد حقول قابلة للتعديل.'});
  const old=await pool.query(`SELECT * FROM ${table} WHERE id=$1`,[req.params.id]); if(!old.rows[0]) return res.status(404).json({error:'السجل غير موجود.'});
  const vals=keys.map(f=>req.body[f] === '' ? null : req.body[f]); vals.push(req.params.id);
  const r=await pool.query(`UPDATE ${table} SET ${keys.map((f,i)=>`${f}=$${i+1}`).join(',')} WHERE id=$${vals.length} RETURNING *`,vals); await audit(req,'update',table,req.params.id,{before:old.rows[0],after:r.rows[0]}); res.json({item:r.rows[0]});
}));
app.delete('/api/:resource/:id', auth, ownerOnly, validResource, asyncRoute(async (req,res) => {
  const {table}=req.resource; const old=await pool.query(`SELECT * FROM ${table} WHERE id=$1`,[req.params.id]); if(!old.rows[0]) return res.status(404).json({error:'السجل غير موجود.'});
  await pool.query(`DELETE FROM ${table} WHERE id=$1`,[req.params.id]); await audit(req,'delete',table,req.params.id,old.rows[0]); res.json({ok:true});
}));
app.get('/api/users', auth, ownerOnly, asyncRoute(async (_req,res)=>{ const r=await pool.query('SELECT id,username,display_name,role,active,created_at FROM users ORDER BY created_at DESC'); res.json({items:r.rows}); }));
app.post('/api/users', auth, ownerOnly, asyncRoute(async (req,res)=>{ const {username,password,displayName,role}=req.body||{}; if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(username||'')||!displayName?.trim()||!password||password.length<12||!['manager','staff','viewer'].includes(role)) return res.status(400).json({error:'تحقق من الاسم وكلمة المرور (12 حرفاً على الأقل) والصلاحية.'}); const hash=await bcrypt.hash(password,12); const r=await pool.query('INSERT INTO users(username,password_hash,display_name,role) VALUES($1,$2,$3,$4) RETURNING id,username,display_name,role,active,created_at',[username,hash,displayName.trim(),role]); await audit(req,'create','user',r.rows[0].id,{username,role}); res.status(201).json({item:r.rows[0]}); }));
app.patch('/api/users/:id', auth, ownerOnly, asyncRoute(async (req,res)=>{ const {active,role,displayName}=req.body||{}; if(String(req.params.id)===String(req.user.id) && (active===false||role&&role!=='owner')) return res.status(400).json({error:'لا يمكنك تعطيل حسابك أو تغيير صلاحية حساب المالك الحالي.'}); const allowedRoles=['owner','manager','staff','viewer']; if(role&&!allowedRoles.includes(role)) return res.status(400).json({error:'الصلاحية غير صحيحة.'}); const r=await pool.query('UPDATE users SET active=COALESCE($1,active),role=COALESCE($2,role),display_name=COALESCE($3,display_name) WHERE id=$4 AND id <> 0 RETURNING id,username,display_name,role,active',[active??null,role??null,displayName??null,req.params.id]); if(!r.rows[0]) return res.status(404).json({error:'المستخدم غير موجود.'}); await audit(req,'update','user',req.params.id,r.rows[0]); res.json({item:r.rows[0]}); }));
app.get('/api/audit', auth, managerOrOwner, asyncRoute(async (_req,res)=>{ const r=await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 300'); res.json({items:r.rows}); }));
app.get('*', (_req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));
app.use((err,_req,res,_next)=>{ console.error(err); if(err.code==='23505') return res.status(409).json({error:'هذا الاسم موجود مسبقاً.'}); res.status(500).json({error:'حدث خطأ داخلي. راجع سجلات الخادم.'}); });
initDb().then(()=>{ const port=process.env.PORT||10000; app.listen(port,()=>console.log(`ELITE ROLEPLAY running on ${port}`)); }).catch(e=>{ console.error('Database initialization failed:',e); process.exit(1); });
