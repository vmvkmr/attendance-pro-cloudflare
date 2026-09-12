// Attendance Pro - single-file Cloudflare Worker
// Selfie-only attendance review. No face authentication/liveness.

// Cloudflare Worker backend for Attendance Pro. No face authentication/liveness.
let supabase;

function json(statusCode, body) {
  return Response.json(body, { status: statusCode, headers: { 'Cache-Control': 'no-store' } });
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function token() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

class QueryBuilder {
  constructor(base, key, table) { this.base=base; this.key=key; this.table=table; this.method='GET'; this.filters=[]; this.params=new URLSearchParams(); this.body=null; this.singleMode=false; }
  select(columns='*') { this.params.set('select', columns); return this; }
  eq(k,v){this.filters.push([k,'eq',v]);return this;} neq(k,v){this.filters.push([k,'neq',v]);return this;}
  gt(k,v){this.filters.push([k,'gt',v]);return this;} gte(k,v){this.filters.push([k,'gte',v]);return this;}
  lt(k,v){this.filters.push([k,'lt',v]);return this;} lte(k,v){this.filters.push([k,'lte',v]);return this;}
  in(k,vals){this.filters.push([k,'in',vals]);return this;}
  order(k,opt={}){this.params.set('order',`${k}.${opt.ascending===false?'desc':'asc'}`);return this;}
  limit(n){this.params.set('limit',String(n));return this;}
  maybeSingle(){this.singleMode=true;this.params.set('limit','1');return this;}
  single(){this.singleMode=true;this.params.set('limit','1');return this;}
  insert(obj){this.method='POST';this.body=obj;return this;}
  update(obj){this.method='PATCH';this.body=obj;return this;}
  delete(){this.method='DELETE';return this;}
  async execute(){
    const qs=new URLSearchParams(this.params);
    for(const [k,op,v] of this.filters){
      const val=op==='in' ? `(${v.map(x=>String(x).replace(/,/g,'\\,')).join(',')})` : String(v);
      qs.set(k,`${op}.${val}`);
    }
    const url=`${this.base}/rest/v1/${this.table}${qs.toString()?`?${qs.toString()}`:''}`;
    const headers={apikey:this.key,Authorization:`Bearer ${this.key}`,Accept:'application/json'};
    let options={method:this.method,headers};
    if(this.body!==null){headers['Content-Type']='application/json';headers['Prefer']='return=representation';options.body=JSON.stringify(this.body);}
    const r=await fetch(url,options); const text=await r.text(); let data=null; try{data=text?JSON.parse(text):null}catch{data=text;}
    if(!r.ok) return {data:null,error:{message:data?.message||data?.error||text||`Supabase HTTP ${r.status}`,status:r.status}};
    if(this.singleMode) return {data:Array.isArray(data)?(data[0]||null):data,error:null};
    return {data,error:null};
  }
  then(resolve,reject){return this.execute().then(resolve,reject);}
}
function makeSupabase(base,key){return {from(table){return new QueryBuilder(base,key,table);}}}

function indiaToday() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date());
}
function dayCount(start, end) {
  const a = new Date(`${start}T00:00:00Z`);
  const b = new Date(`${end}T00:00:00Z`);
  return Math.floor((b-a)/86400000)+1;
}
function balanceField(type) {
  return type === 'Special' ? 'special' : type.toLowerCase();
}
function isSunday(dateStr) {
  const d = new Date(`${dateStr}T00:00:00Z`);
  return d.getUTCDay() === 0;
}
function monthBounds(month) {
  const [y,m] = String(month).split('-').map(Number);
  const last = new Date(Date.UTC(y, m, 0)).toISOString().slice(0,10);
  return [`${month}-01`, last];
}
function roundMoney(n) { return Math.round((Number(n)||0) * 100) / 100; }

async function userForSession(session) {
  if (!session) return null;
  const { data: s } = await supabase.from('attendance_sessions').select('user_id,expires_at').eq('token',session).maybeSingle();
  if (!s || new Date(s.expires_at) <= new Date()) return null;
  const { data: u } = await supabase.from('users').select('id,name,role,active,per_day,email').eq('id',s.user_id).maybeSingle();
  return u?.active ? u : null;
}
async function requireAdmin(session) {
  const u = await userForSession(session);
  if (!u || u.role !== 'admin') throw new Error('Admin access required.');
  return u;
}

const apiWorker = {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
    const SUPABASE_URL = env.SUPABASE_URL;
    const SUPABASE_KEY = env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_SERVICE_ROLE;
    if (!SUPABASE_URL || !SUPABASE_KEY) return Response.json({error:'Cloudflare environment is missing SUPABASE_URL and SUPABASE_SECRET_KEY.'},{status:500});
    supabase = makeSupabase(SUPABASE_URL, SUPABASE_KEY);
    try {
    const body = await request.json().catch(() => ({}));
    const action = body.action;

    if (action === 'login') {
      const id = String(body.id ?? '').trim();
      const password = String(body.password ?? '');
      if (!id || !password) return json(400,{error:'User ID and password are required.'});

      const { data: u, error: userError } = await supabase
        .from('users')
        .select('id,name,role,active,per_day,email,password,password_hash')
        .eq('id', id)
        .maybeSingle();

      if (userError) {
        console.error('LOGIN_DB_ERROR', userError);
        return json(500,{error:'Login database error: ' + userError.message});
      }
      if (!u || u.active !== true) return json(401,{error:'Invalid User ID or password.'});

      const hashed = await sha256(password);
      const valid = [u.password_hash, u.password].some(v => v != null && (String(v) === password || String(v) === hashed));
      if (!valid) return json(401,{error:'Invalid User ID or password.'});

      const t = token();
      const { error: deleteError } = await supabase.from('attendance_sessions').delete().eq('user_id', id);
      if (deleteError) {
        console.error('LOGIN_SESSION_DELETE_ERROR', deleteError);
        return json(500,{error:'Login session error: ' + deleteError.message});
      }
      const { error: insertError } = await supabase.from('attendance_sessions').insert({token:t,user_id:id});
      if (insertError) {
        console.error('LOGIN_SESSION_INSERT_ERROR', insertError);
        return json(500,{error:'Login session error: ' + insertError.message});
      }

      return json(200,{session:t,user:{id:u.id,name:u.name,role:u.role,per_day:u.per_day,email:u.email}});
    }

    const session = body.session;
    const user = await userForSession(session);
    if (!user) return json(401,{error:'Session expired. Please sign in again.'});

    if (action === 'me') return json(200,{user});

    if (action === 'my_attendance') {
      const { data, error } = await supabase.from('attendance').select('id,user_id,attendance_date,status,reason,approved_at,latitude,longitude,location_accuracy').eq('user_id',user.id).order('attendance_date',{ascending:false}).limit(120);
      if (error) throw error;
      return json(200,{items:data||[]});
    }

    if (action === 'submit_attendance') {
      const date = indiaToday();
      if (body.attendance_date !== date) return json(400,{error:'Attendance date is controlled by the server.'});
      if (!body.latitude || !body.longitude) return json(400,{error:'Location is required.'});
      if (!body.selfie_data) return json(400,{error:'Selfie is required.'});
      const sunday = isSunday(date);
      if (sunday) {
        const {data:req} = await supabase.from('sunday_work_requests').select('status,reason').eq('user_id',user.id).eq('work_date',date).maybeSingle();
        if (!req || req.status !== 'approved') return json(403,{error:'Sunday is OFF. Admin approval is required before Sunday attendance.'});
      }
      const { data: existing } = await supabase.from('attendance').select('id').eq('user_id',user.id).eq('attendance_date',date).maybeSingle();
      if (existing) return json(409,{error:'Attendance has already been submitted for today.'});
      const { error } = await supabase.from('attendance').insert({
        user_id:user.id, attendance_date:date, status:'pending',
        reason:String(body.reason||'').slice(0,500),
        selfie_data:String(body.selfie_data).slice(0,450000),
        latitude:Number(body.latitude), longitude:Number(body.longitude),
        location_accuracy:Number(body.accuracy||body.location_accuracy||0)
      });
      if (error) throw error;
      return json(200,{ok:true});
    }

    if (action === 'my_sunday_requests') {
      const {data,error}=await supabase.from('sunday_work_requests').select('id,work_date,reason,status,requested_at,reviewed_at').eq('user_id',user.id).order('work_date',{ascending:false}).limit(60);
      if(error) throw error;
      return json(200,{items:data||[]});
    }

    if (action === 'request_sunday_work') {
      const date=String(body.work_date||'');
      if(!date || !isSunday(date)) return json(400,{error:'Select a Sunday date.'});
      if(date < indiaToday()) return json(400,{error:'Past dates cannot be requested.'});
      const reason=String(body.reason||'').trim();
      if(!reason) return json(400,{error:'Sunday work reason is required.'});
      const {data:existing}=await supabase.from('sunday_work_requests').select('id,status').eq('user_id',user.id).eq('work_date',date).maybeSingle();
      if(existing) return json(409,{error:`A request already exists for this Sunday (${existing.status}).`});
      const {error}=await supabase.from('sunday_work_requests').insert({user_id:user.id,work_date:date,reason:reason.slice(0,500),status:'pending'});
      if(error) throw error;
      return json(200,{ok:true});
    }

    if (action === 'my_salary') {
      const month=String(body.month||indiaToday().slice(0,7));
      const [from,to]=monthBounds(month);
      const [{data:atts,error:ae},{data:leaves,error:le},{data:u,error:ue}]=await Promise.all([
        supabase.from('attendance').select('attendance_date,status').eq('user_id',user.id).gte('attendance_date',from).lte('attendance_date',to),
        supabase.from('leaves').select('leave_date,end_date,status').eq('user_id',user.id).eq('status','approved').lte('leave_date',to).gte('end_date',from),
        supabase.from('users').select('per_day').eq('id',user.id).maybeSingle()
      ]);
      if(ae||le||ue) throw (ae||le||ue);
      const rate=Number(u?.per_day||0);
      let present=0,half=0,sunday=0;
      for(const a of (atts||[])){ if(a.status==='approved'||a.status==='present') present+=1; else if(a.status==='half_day') half+=1; }
      const {data:sreq}=await supabase.from('sunday_work_requests').select('work_date,status').eq('user_id',user.id).eq('status','approved').gte('work_date',from).lte('work_date',to);
      const approvedSundays=new Set((sreq||[]).map(x=>x.work_date));
      for(const a of (atts||[])) if(isSunday(a.attendance_date) && approvedSundays.has(a.attendance_date) && (a.status==='approved'||a.status==='present')) sunday+=1;
      let paidLeave=0;
      for(const l of (leaves||[])){ const a=new Date(`${l.leave_date}T00:00:00Z`), b=new Date(`${l.end_date||l.leave_date}T00:00:00Z`); const lo=new Date(`${from}T00:00:00Z`), hi=new Date(`${to}T00:00:00Z`); const start=Math.max(a,lo), end=Math.min(b,hi); if(end>=start) paidLeave += Math.floor((end-start)/86400000)+1; }
      const gross=roundMoney(rate*(present+half*0.5+paidLeave+sunday));
      const pfBase=Math.min(gross,15000);
      const pf=roundMoney(pfBase*0.12);
      const esi= gross<=21000 ? roundMoney(gross*0.0075) : 0;
      const net=roundMoney(gross-pf-esi);
      return json(200,{month,per_day:rate,present_days:present,half_days:half,paid_leave_days:paidLeave,sunday_days:sunday,gross_salary:gross,pf_employee:pf,esi_employee:esi,net_salary:net});
    }

    if (action === 'admin_sunday_requests') {
      await requireAdmin(session);
      const {data,error}=await supabase.from('sunday_work_requests').select('id,user_id,work_date,reason,status,requested_at').order('work_date',{ascending:false}).limit(200);
      if(error) throw error;
      const ids=[...(new Set((data||[]).map(x=>x.user_id)))]; const {data:users}=ids.length?await supabase.from('users').select('id,name,per_day').in('id',ids):{data:[]};
      const names=Object.fromEntries((users||[]).map(x=>[x.id,{name:x.name,per_day:x.per_day}]));
      return json(200,{items:(data||[]).map(x=>({...x,user_name:names[x.user_id]?.name||x.user_id,per_day:names[x.user_id]?.per_day||0}))});
    }

    if (action === 'review_sunday_request') {
      const admin=await requireAdmin(session); const id=Number(body.id);
      const status=body.approve?'approved':'rejected';
      const {error}=await supabase.from('sunday_work_requests').update({status,reviewed_at:new Date().toISOString(),reviewed_by:admin.id}).eq('id',id).eq('status','pending');
      if(error) throw error; return json(200,{ok:true});
    }

    if (action === 'my_leaves') {
      const [l,b] = await Promise.all([
        supabase.from('leaves').select('id,leave_date,end_date,leave_type,reason,status,rollback_status,created_at').eq('user_id',user.id).order('leave_date',{ascending:false}).limit(100),
        supabase.from('leave_balances').select('pl,cl,sl,special').eq('user_id',user.id).maybeSingle()
      ]);
      if (l.error) throw l.error;
      return json(200,{items:l.data||[],balance:b.data||{pl:24,cl:6,sl:4,special:10}});
    }

    if (action === 'apply_leave') {
      const type = body.leave_type;
      const start = body.leave_date;
      const end = body.end_date || start;
      if (!['PL','CL','SL','Special'].includes(type)) return json(400,{error:'Invalid leave type.'});
      if (!start || !end || end < start) return json(400,{error:'Invalid leave dates.'});
      const days = dayCount(start,end);
      const field = balanceField(type);
      const { data:b } = await supabase.from('leave_balances').select('*').eq('user_id',user.id).maybeSingle();
      if (!b || Number(b[field]) < days) return json(400,{error:`Insufficient ${type} balance.`});
      const { data:overlap } = await supabase.from('leaves').select('id').eq('user_id',user.id).neq('status','rejected').lte('leave_date',end).gte('end_date',start).limit(1);
      if (overlap?.length) return json(409,{error:'A leave request already covers these dates.'});
      const { error } = await supabase.from('leaves').insert({user_id:user.id,leave_date:start,end_date:end,leave_type:type,reason:String(body.reason||'').slice(0,500),status:'pending'});
      if (error) throw error;
      return json(200,{ok:true});
    }

    if (action === 'request_rollback') {
      const leaveId = Number(body.leave_id);
      const { data:l } = await supabase.from('leaves').select('id,status,rollback_status').eq('id',leaveId).eq('user_id',user.id).maybeSingle();
      if (!l || l.status !== 'approved') return json(400,{error:'Only approved leave can be rolled back.'});
      if (l.rollback_status !== 'none') return json(400,{error:'A rollback request already exists.'});
      const { error } = await supabase.from('leave_rollbacks').insert({leave_id:leaveId,user_id:user.id,reason:String(body.reason||'').slice(0,500),status:'pending'});
      if (error) throw error;
      await supabase.from('leaves').update({rollback_requested:true,rollback_status:'pending'}).eq('id',leaveId);
      return json(200,{ok:true});
    }

    if (action === 'admin_attendance') {
      await requireAdmin(session);
      const { data, error } = await supabase.from('attendance').select('id,user_id,attendance_date,status,reason,selfie_data,latitude,longitude,location_accuracy,approved_at,created_at').order('attendance_date',{ascending:false}).limit(300);
      if (error) throw error;
      const ids=[...(new Set((data||[]).map(x=>x.user_id)))];
      const {data:users}=ids.length?await supabase.from('users').select('id,name').in('id',ids):{data:[]};
      const names=Object.fromEntries((users||[]).map(x=>[x.id,x.name]));
      return json(200,{items:(data||[]).map(x=>({...x,user_name:names[x.user_id]||x.user_id}))});
    }

    if (action === 'review_attendance') {
      const admin=await requireAdmin(session);
      const id=Number(body.id);
      const status=body.approve?'approved':'absent';
      const {error}=await supabase.from('attendance').update({status,approved_by:admin.id,approved_at:new Date().toISOString()}).eq('id',id);
      if(error)throw error;
      return json(200,{ok:true});
    }

    if (action === 'admin_leaves') {
      await requireAdmin(session);
      const {data,error}=await supabase.from('leaves').select('id,user_id,leave_date,end_date,leave_type,reason,status,rollback_status,created_at').order('leave_date',{ascending:false}).limit(300);
      if(error)throw error;
      const ids=[...(new Set((data||[]).map(x=>x.user_id)))];
      const {data:users}=ids.length?await supabase.from('users').select('id,name').in('id',ids):{data:[]};
      const names=Object.fromEntries((users||[]).map(x=>[x.id,x.name]));
      return json(200,{items:(data||[]).map(x=>({...x,user_name:names[x.user_id]||x.user_id}))});
    }

    if (action === 'review_leave') {
      const admin=await requireAdmin(session);
      const id=Number(body.id);
      const {data:l}=await supabase.from('leaves').select('*').eq('id',id).maybeSingle();
      if(!l || l.status!=='pending') return json(400,{error:'Leave is not pending.'});
      if(body.approve){
        const days=dayCount(l.leave_date,l.end_date||l.leave_date), field=balanceField(l.leave_type);
        const {data:b}=await supabase.from('leave_balances').select('*').eq('user_id',l.user_id).maybeSingle();
        if(!b || Number(b[field])<days) return json(400,{error:'Insufficient leave balance at approval time.'});
        await supabase.from('leave_balances').update({[field]:Number(b[field])-days,updated_at:new Date().toISOString()}).eq('user_id',l.user_id);
        await supabase.from('leaves').update({status:'approved'}).eq('id',id);
      } else {
        await supabase.from('leaves').update({status:'rejected'}).eq('id',id);
      }
      return json(200,{ok:true,admin:admin.id});
    }

    if (action === 'review_rollback') {
      const admin=await requireAdmin(session);
      const id=Number(body.id);
      const {data:l}=await supabase.from('leaves').select('*').eq('id',id).maybeSingle();
      if(!l || l.rollback_status!=='pending') return json(400,{error:'Rollback is not pending.'});
      const {data:r}=await supabase.from('leave_rollbacks').select('*').eq('leave_id',id).eq('status','pending').maybeSingle();
      if(body.approve){
        const days=dayCount(l.leave_date,l.end_date||l.leave_date), field=balanceField(l.leave_type);
        const {data:b}=await supabase.from('leave_balances').select('*').eq('user_id',l.user_id).maybeSingle();
        await supabase.from('leave_balances').update({[field]:Number(b?.[field]||0)+days,updated_at:new Date().toISOString()}).eq('user_id',l.user_id);
        await supabase.from('leaves').update({status:'rejected',rollback_status:'approved',rollback_requested:true}).eq('id',id);
      } else {
        await supabase.from('leaves').update({rollback_status:'rejected',rollback_requested:true}).eq('id',id);
      }
      if(r) await supabase.from('leave_rollbacks').update({status:body.approve?'approved':'rejected',reviewed_at:new Date().toISOString(),reviewed_by:admin.id}).eq('id',r.id);
      return json(200,{ok:true});
    }

    if (action === 'admin_salary') {
      await requireAdmin(session);
      const month=String(body.month||indiaToday().slice(0,7)); const [from,to]=monthBounds(month);
      const [{data:users,error:ue},{data:atts,error:ae},{data:leaves,error:le},{data:sreq,error:se}]=await Promise.all([
        supabase.from('users').select('id,name,per_day,active').eq('role','user').order('id'),
        supabase.from('attendance').select('user_id,attendance_date,status').gte('attendance_date',from).lte('attendance_date',to),
        supabase.from('leaves').select('user_id,leave_date,end_date,status').eq('status','approved').lte('leave_date',to).gte('end_date',from),
        supabase.from('sunday_work_requests').select('user_id,work_date,status').eq('status','approved').gte('work_date',from).lte('work_date',to)
      ]); if(ue||ae||le||se) throw (ue||ae||le||se);
      const rows=(users||[]).map(u=>{ const ua=(atts||[]).filter(a=>a.user_id===u.id); let present=0,half=0,sunday=0; const ss=new Set((sreq||[]).filter(x=>x.user_id===u.id).map(x=>x.work_date)); for(const a of ua){if(a.status==='approved'||a.status==='present')present++; else if(a.status==='half_day')half++; if(isSunday(a.attendance_date)&&ss.has(a.attendance_date)&&(a.status==='approved'||a.status==='present'))sunday++;} let paidLeave=0; for(const l of (leaves||[]).filter(x=>x.user_id===u.id)){const a=new Date(`${l.leave_date}T00:00:00Z`),b=new Date(`${l.end_date||l.leave_date}T00:00:00Z`),lo=new Date(`${from}T00:00:00Z`),hi=new Date(`${to}T00:00:00Z`);const st=Math.max(a,lo),en=Math.min(b,hi);if(en>=st)paidLeave+=Math.floor((en-st)/86400000)+1;} const rate=Number(u.per_day||0),gross=roundMoney(rate*(present+half*.5+paidLeave+sunday)),pf=roundMoney(Math.min(gross,15000)*.12),esi=gross<=21000?roundMoney(gross*.0075):0;return {user_id:u.id,name:u.name,per_day:rate,present_days:present,half_days:half,paid_leave_days:paidLeave,sunday_days:sunday,gross_salary:gross,pf_employee:pf,esi_employee:esi,net_salary:roundMoney(gross-pf-esi)};});
      return json(200,{month,items:rows});
    }

    if (action === 'admin_users') {
      await requireAdmin(session);
      const {data,error}=await supabase.from('users').select('id,name,role,active,per_day,email,created_at').order('id');
      if(error)throw error;
      return json(200,{items:data||[]});
    }

    if (action === 'create_user') {
      await requireAdmin(session);
      const id=String(body.id||'').trim(), name=String(body.name||'').trim(), password=String(body.password||'');
      if(!id||!name||password.length<4)return json(400,{error:'User ID, name and a 4+ character password are required.'});
      const {data:exists}=await supabase.from('users').select('id').eq('id',id).maybeSingle();
      if(exists)return json(409,{error:'User ID already exists.'});
      const {error}=await supabase.from('users').insert({id,name,role:body.role==='admin'?'admin':'user',active:true,per_day:Number(body.per_day||0),password_hash:await sha256(password),password:await sha256(password)});
      if(error)throw error;
      await supabase.from('leave_balances').insert({user_id:id,pl:24,cl:6,sl:4,special:10});
      return json(200,{ok:true});
    }

    if (action === 'reset_password') {
      await requireAdmin(session);
      const id=String(body.id||''), password=String(body.password||'');
      if(password.length<4)return json(400,{error:'Password must be at least 4 characters.'});
      const {error}=await supabase.from('users').update({password_hash:await sha256(password),password:await sha256(password)}).eq('id',id);
      if(error)throw error;
      return json(200,{ok:true});
    }

    return json(400,{error:'Unknown action.'});
    } catch (e) {
      console.error(e);
      return json(500,{error:e?.message||'Server error'});
    }
  }
};

const INDEX_HTML = "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n  <meta name=\"theme-color\" content=\"#0f172a\" />\n  <title>Attendance Pro</title>\n  <link rel=\"stylesheet\" href=\"/styles.css\">\n</head>\n<body>\n  <div id=\"root\"></div>\n  <script src=\"https://unpkg.com/react@18.3.1/umd/react.production.min.js\"></script>\n  <script src=\"https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js\"></script>\n  <script src=\"/app.js\"></script>\n</body>\n</html>\n";
const APP_JS = "const { useEffect, useMemo, useRef, useState } = React;\nconst makeIcon = (symbol) => function Icon({ size = 18 }) { return React.createElement('span', { style: { display: 'inline-flex', width: size, height: size, alignItems: 'center', justifyContent: 'center', fontSize: Math.max(12, Math.round(size * 0.72)), lineHeight: 1 } }, symbol); };\nconst Camera = makeIcon('\ud83d\udcf7'), MapPin = makeIcon('\ud83d\udccd'), CalendarDays = makeIcon('\ud83d\udcc5'), ClipboardCheck = makeIcon('\u2611'), LogOut = makeIcon('\u21aa'), Users = makeIcon('\ud83d\udc65'), RotateCcw = makeIcon('\u21b6'), KeyRound = makeIcon('\ud83d\udd11'), Plus = makeIcon('+'), Check = makeIcon('\u2713'), X = makeIcon('\u00d7'), UserPlus = makeIcon('\ud83d\udc64'), Wallet = makeIcon('\u20b9'), Clock = makeIcon('\u25f7');\nconst api = async (action, body = {}) => {\n    const res = await fetch('/api/attendance', {\n        method: 'POST',\n        headers: { 'Content-Type': 'application/json' },\n        body: JSON.stringify({ action, ...body })\n    });\n    const data = await res.json().catch(() => ({ error: 'Invalid server response' }));\n    if (!res.ok)\n        throw new Error(data.error || 'Request failed');\n    return data;\n};\nconst today = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date());\nconst isSundayDate = (value) => { const d = new Date(`${value}T00:00:00Z`); return d.getUTCDay() === 0; };\nconst nextSunday = () => { const d = new Date(`${today()}T00:00:00Z`); const add = (7 - d.getUTCDay()) % 7 || 7; d.setUTCDate(d.getUTCDate() + add); return d.toISOString().slice(0, 10); };\nfunction App() {\n    const [session, setSession] = useState(() => localStorage.getItem('attendance_session') || '');\n    const [me, setMe] = useState(null);\n    const [tab, setTab] = useState('attendance');\n    const [notice, setNotice] = useState('');\n    const [error, setError] = useState('');\n    const loadMe = async () => {\n        if (!session)\n            return;\n        try {\n            const data = await api('me', { session });\n            setMe(data.user);\n        }\n        catch {\n            localStorage.removeItem('attendance_session');\n            setSession('');\n            setMe(null);\n        }\n    };\n    useEffect(() => { loadMe(); }, [session]);\n    if (!session || !me) {\n        return React.createElement(Login, { onLogin: (token) => {\n                localStorage.setItem('attendance_session', token);\n                setSession(token);\n            } });\n    }\n    const logout = () => {\n        localStorage.removeItem('attendance_session');\n        setSession('');\n        setMe(null);\n    };\n    const flash = (msg) => { setNotice(msg); setError(''); setTimeout(() => setNotice(''), 3500); };\n    const fail = (msg) => { setError(msg); setNotice(''); };\n    return (React.createElement(\"div\", { className: \"app-shell\" },\n        React.createElement(\"header\", { className: \"topbar\" },\n            React.createElement(\"div\", null,\n                React.createElement(\"div\", { className: \"brand\" }, \"Attendance Pro\"),\n                React.createElement(\"div\", { className: \"subbrand\" },\n                    me.name,\n                    \" \\u00B7 \",\n                    me.role === 'admin' ? 'Administrator' : 'Employee')),\n            React.createElement(\"button\", { className: \"icon-btn\", onClick: logout, title: \"Logout\" },\n                React.createElement(LogOut, { size: 18 }))),\n        notice && React.createElement(\"div\", { className: \"toast success\" }, notice),\n        error && React.createElement(\"div\", { className: \"toast error\" }, error),\n        me.role === 'admin' ? (React.createElement(AdminView, { session: session, flash: flash, fail: fail })) : (React.createElement(React.Fragment, null,\n            React.createElement(\"nav\", { className: \"tabs\" },\n                React.createElement(\"button\", { className: tab === 'attendance' ? 'active' : '', onClick: () => setTab('attendance') },\n                    React.createElement(ClipboardCheck, { size: 17 }),\n                    \" Attendance\"),\n                React.createElement(\"button\", { className: tab === 'leave' ? 'active' : '', onClick: () => setTab('leave') },\n                    React.createElement(CalendarDays, { size: 17 }),\n                    \" Leave\"),\n                React.createElement(\"button\", { className: tab === 'records' ? 'active' : '', onClick: () => setTab('records') },\n                    React.createElement(Users, { size: 17 }),\n                    \" My Records\"),\n                React.createElement(\"button\", { className: tab === 'salary' ? 'active' : '', onClick: () => setTab('salary') },\n                    React.createElement(Wallet, { size: 17 }),\n                    \" Payment\")),\n            tab === 'attendance' && React.createElement(AttendanceTab, { session: session, user: me, flash: flash, fail: fail }),\n            tab === 'leave' && React.createElement(LeaveTab, { session: session, flash: flash, fail: fail }),\n            tab === 'records' && React.createElement(RecordsTab, { session: session }),\n            tab === 'salary' && React.createElement(SalaryTab, { session: session })))));\n}\nfunction Login({ onLogin }) {\n    const [id, setId] = useState('');\n    const [password, setPassword] = useState('');\n    const [error, setError] = useState('');\n    const submit = async (e) => {\n        e.preventDefault();\n        setError('');\n        try {\n            const data = await api('login', { id, password });\n            onLogin(data.session);\n        }\n        catch (e) {\n            setError(e.message);\n        }\n    };\n    return React.createElement(\"div\", { className: \"login-wrap\" },\n        React.createElement(\"form\", { className: \"card login-card\", onSubmit: submit },\n            React.createElement(\"h1\", null, \"Attendance Pro\"),\n            React.createElement(\"p\", { className: \"muted\" }, \"Secure attendance and leave management\"),\n            React.createElement(\"label\", null,\n                \"User ID\",\n                React.createElement(\"input\", { value: id, onChange: e => setId(e.target.value), autoComplete: \"username\", required: true })),\n            React.createElement(\"label\", null,\n                \"Password\",\n                React.createElement(\"input\", { type: \"password\", value: password, onChange: e => setPassword(e.target.value), autoComplete: \"current-password\", required: true })),\n            error && React.createElement(\"div\", { className: \"inline-error\" }, error),\n            React.createElement(\"button\", { className: \"primary full\" }, \"Sign in\")));\n}\nfunction AttendanceTab({ session, user, flash, fail }) {\n    const videoRef = useRef(null);\n    const canvasRef = useRef(null);\n    const [camera, setCamera] = useState(false);\n    const [photo, setPhoto] = useState('');\n    const [location, setLocation] = useState(null);\n    const [existing, setExisting] = useState(null);\n    const [sundayRequest, setSundayRequest] = useState(null);\n    const [sundayReason, setSundayReason] = useState('');\n    const [sundayDate, setSundayDate] = useState(nextSunday());\n    const [todaySundayApproved, setTodaySundayApproved] = useState(false);\n    const [todaySundayReason, setTodaySundayReason] = useState('');\n    const [loading, setLoading] = useState(true);\n    useEffect(() => {\n        load();\n        requestLocation();\n        return () => stopCamera();\n    }, []);\n    useEffect(() => {\n        api('my_sunday_requests', { session }).then(sr => { setSundayRequest(sr.items.find(x => x.work_date === sundayDate) || null); {\n            const tr = sr.items.find(x => x.work_date === today() && x.status === 'approved');\n            setTodaySundayApproved(!!tr);\n            setTodaySundayReason(tr?.reason || 'Approved Sunday work');\n        } }).catch(() => { });\n    }, [sundayDate]);\n    const load = async () => {\n        try {\n            const d = await api('my_attendance', { session });\n            setExisting(d.items.find(x => x.attendance_date === today()) || null);\n            const sr = await api('my_sunday_requests', { session });\n            setSundayRequest(sr.items.find(x => x.work_date === sundayDate) || null);\n            {\n                const tr = sr.items.find(x => x.work_date === today() && x.status === 'approved');\n                setTodaySundayApproved(!!tr);\n                setTodaySundayReason(tr?.reason || 'Approved Sunday work');\n            }\n        }\n        catch (e) {\n            fail(e.message);\n        }\n        finally {\n            setLoading(false);\n        }\n    };\n    const requestLocation = () => {\n        if (!navigator.geolocation)\n            return fail('This browser does not support location.');\n        navigator.geolocation.getCurrentPosition(p => setLocation({ latitude: p.coords.latitude, longitude: p.coords.longitude, accuracy: p.coords.accuracy }), () => fail('Location permission is required to submit attendance. Please allow location access.'), { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 });\n    };\n    const startCamera = async () => {\n        try {\n            if (!navigator.mediaDevices?.getUserMedia) {\n                return fail('Camera is not available in this browser. Please open the app directly in Chrome/Edge and allow camera access.');\n            }\n            const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'user' } }, audio: false });\n            setCamera(true);\n            requestAnimationFrame(async () => {\n                const video = videoRef.current;\n                if (!video) {\n                    stream.getTracks().forEach(t => t.stop());\n                    return fail('Camera preview could not be opened. Please refresh and try again.');\n                }\n                video.srcObject = stream;\n                try {\n                    await video.play();\n                }\n                catch {\n                    fail('Camera preview could not start. Please allow camera access and try again.');\n                }\n            });\n        }\n        catch (e) {\n            const name = e?.name;\n            if (name === 'NotAllowedError' || name === 'PermissionDeniedError') {\n                fail('Camera permission was blocked. Click the camera icon in the browser address bar and choose Allow, then refresh.');\n            }\n            else if (name === 'NotFoundError' || name === 'DevicesNotFoundError') {\n                fail('No camera was found on this device.');\n            }\n            else {\n                fail('Unable to open camera. Please allow camera access and try again.');\n            }\n        }\n    };\n    const stopCamera = () => {\n        const stream = videoRef.current?.srcObject;\n        stream?.getTracks().forEach(t => t.stop());\n        if (videoRef.current)\n            videoRef.current.srcObject = null;\n        setCamera(false);\n    };\n    const takePhoto = () => {\n        const video = videoRef.current;\n        const canvas = canvasRef.current;\n        if (!video || !canvas)\n            return;\n        canvas.width = 640;\n        canvas.height = Math.round(640 * (video.videoHeight / video.videoWidth || 0.75));\n        canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);\n        setPhoto(canvas.toDataURL('image/jpeg', 0.62));\n        stopCamera();\n    };\n    const submit = async () => {\n        if (!location)\n            return fail('Location is not available. Allow location and try again.');\n        if (!photo)\n            return fail('Take a selfie before submitting.');\n        const d = new Date();\n        const weekday = d.toLocaleDateString('en-IN', { weekday: 'long', timeZone: 'Asia/Kolkata' });\n        let reason = '';\n        if (weekday === 'Sunday') {\n            if (!sundayRequest || sundayRequest.status !== 'approved')\n                return fail('Sunday is OFF. First request Sunday work and wait for admin approval.');\n            reason = todaySundayReason || 'Approved Sunday work';\n        }\n        try {\n            await api('submit_attendance', { session, attendance_date: today(), reason, selfie_data: photo, ...location });\n            flash('Attendance submitted. Waiting for admin approval.');\n            await load();\n        }\n        catch (e) {\n            fail(e.message);\n        }\n    };\n    return React.createElement(\"main\", { className: \"content\" },\n        React.createElement(\"div\", { className: \"card hero-card\" },\n            React.createElement(\"div\", { className: \"date-lock\" },\n                React.createElement(\"div\", null,\n                    React.createElement(\"span\", { className: \"eyebrow\" }, \"Attendance date\"),\n                    React.createElement(\"strong\", null, today())),\n                React.createElement(\"span\", { className: \"locked\" }, \"Locked\")),\n            React.createElement(\"p\", { className: \"muted\" }, \"Date is controlled by the system. You cannot change it.\"),\n            React.createElement(\"div\", { className: \"location-status\" },\n                React.createElement(MapPin, { size: 18 }),\n                React.createElement(\"span\", null, location ? `Location captured (\u00b1${Math.round(location.accuracy || 0)} m)` : 'Requesting location permission\u2026'),\n                !location && React.createElement(\"button\", { className: \"small-btn\", onClick: requestLocation }, \"Enable\")),\n            React.createElement(\"div\", { className: \"status-box\" },\n                React.createElement(\"strong\", null, \"Sunday Work\"),\n                React.createElement(\"div\", { className: \"muted\" }, \"Sunday is weekly OFF. If you need to work on Sunday, request Admin approval first. Approved Sunday attendance gets 2\\u00D7 pay.\"),\n                React.createElement(\"div\", { className: \"form-grid\" },\n                    React.createElement(\"label\", null,\n                        \"Sunday date\",\n                        React.createElement(\"input\", { type: \"date\", value: sundayDate, onChange: e => setSundayDate(e.target.value) })),\n                    React.createElement(\"label\", null,\n                        \"Reason\",\n                        React.createElement(\"textarea\", { placeholder: \"Reason for Sunday work\", value: sundayReason, onChange: e => setSundayReason(e.target.value) }))),\n                React.createElement(\"div\", { className: \"button-row\" },\n                    React.createElement(\"button\", { className: \"secondary\", disabled: !isSundayDate(sundayDate) || sundayRequest?.status === 'pending', onClick: async () => { try {\n                            await api('request_sunday_work', { session, work_date: sundayDate, reason: sundayReason });\n                            flash('Sunday work request sent to admin.');\n                            const sr = await api('my_sunday_requests', { session });\n                            setSundayRequest(sr.items.find(x => x.work_date === sundayDate) || null);\n                        }\n                        catch (e) {\n                            fail(e.message);\n                        } } },\n                        React.createElement(Clock, { size: 17 }),\n                        \" \",\n                        sundayRequest?.status === 'pending' ? 'Request pending' : 'Request Sunday work'),\n                    sundayRequest?.status && React.createElement(\"span\", { className: `pill ${sundayRequest.status}` }, sundayRequest.status))),\n            existing ? React.createElement(\"div\", { className: \"status-box\" },\n                React.createElement(\"strong\", null, \"Today's status:\"),\n                \" \",\n                existing.status) : (new Date(`${today()}T00:00:00Z`).getUTCDay() === 0 && sundayRequest?.status !== 'approved') ? null : React.createElement(React.Fragment, null,\n                React.createElement(\"div\", { className: \"camera-box\" }, camera ? React.createElement(\"video\", { ref: videoRef, playsInline: true, muted: true }) : photo ? React.createElement(\"img\", { src: photo, alt: \"Attendance selfie\" }) : React.createElement(\"div\", { className: \"camera-placeholder\" },\n                    React.createElement(Camera, { size: 34 }),\n                    React.createElement(\"span\", null, \"Selfie required\"))),\n                React.createElement(\"canvas\", { ref: canvasRef, hidden: true }),\n                React.createElement(\"div\", { className: \"button-row\" },\n                    !camera && !photo && React.createElement(\"button\", { className: \"secondary\", onClick: startCamera },\n                        React.createElement(Camera, { size: 18 }),\n                        \" Open camera\"),\n                    camera && React.createElement(\"button\", { className: \"primary\", onClick: takePhoto },\n                        React.createElement(Camera, { size: 18 }),\n                        \" Capture selfie\"),\n                    photo && React.createElement(\"button\", { className: \"secondary\", onClick: startCamera }, \"Retake\"),\n                    photo && React.createElement(\"button\", { className: \"primary\", onClick: submit },\n                        React.createElement(ClipboardCheck, { size: 18 }),\n                        \" Submit attendance\")))));\n}\nfunction LeaveTab({ session, flash, fail }) {\n    const [items, setItems] = useState([]);\n    const [balance, setBalance] = useState(null);\n    const [type, setType] = useState('CL');\n    const [start, setStart] = useState(today());\n    const [end, setEnd] = useState(today());\n    const [reason, setReason] = useState('');\n    const load = async () => {\n        try {\n            const d = await api('my_leaves', { session });\n            setItems(d.items);\n            setBalance(d.balance);\n        }\n        catch (e) {\n            fail(e.message);\n        }\n    };\n    useEffect(() => { load(); }, []);\n    const apply = async (e) => {\n        e.preventDefault();\n        try {\n            await api('apply_leave', { session, leave_type: type, leave_date: start, end_date: end, reason });\n            flash('Leave request submitted.');\n            setReason('');\n            await load();\n        }\n        catch (e) {\n            fail(e.message);\n        }\n    };\n    const rollback = async (id) => {\n        const r = window.prompt('Rollback reason:');\n        if (r === null)\n            return;\n        try {\n            await api('request_rollback', { session, leave_id: id, reason: r });\n            flash('Rollback request sent to admin.');\n            await load();\n        }\n        catch (e) {\n            fail(e.message);\n        }\n    };\n    return React.createElement(\"main\", { className: \"content\" },\n        React.createElement(\"div\", { className: \"balance-grid\" }, balance && [['PL', balance.pl], ['CL', balance.cl], ['SL', balance.sl], ['Special', balance.special]].map(([k, v]) => React.createElement(\"div\", { className: \"balance card\", key: k },\n            React.createElement(\"span\", null, k),\n            React.createElement(\"strong\", null, v),\n            React.createElement(\"small\", null, \"days left\")))),\n        React.createElement(\"form\", { className: \"card\", onSubmit: apply },\n            React.createElement(\"h2\", null, \"Apply Leave\"),\n            React.createElement(\"div\", { className: \"form-grid\" },\n                React.createElement(\"label\", null,\n                    \"Leave type\",\n                    React.createElement(\"select\", { value: type, onChange: e => setType(e.target.value) },\n                        React.createElement(\"option\", null, \"PL\"),\n                        React.createElement(\"option\", null, \"CL\"),\n                        React.createElement(\"option\", null, \"SL\"),\n                        React.createElement(\"option\", null, \"Special\"))),\n                React.createElement(\"label\", null,\n                    \"From\",\n                    React.createElement(\"input\", { type: \"date\", value: start, onChange: e => setStart(e.target.value), required: true })),\n                React.createElement(\"label\", null,\n                    \"To\",\n                    React.createElement(\"input\", { type: \"date\", value: end, onChange: e => setEnd(e.target.value), min: start, required: true })),\n                React.createElement(\"label\", { className: \"wide\" },\n                    \"Reason\",\n                    React.createElement(\"textarea\", { value: reason, onChange: e => setReason(e.target.value), required: true }))),\n            React.createElement(\"button\", { className: \"primary\" },\n                React.createElement(CalendarDays, { size: 17 }),\n                \" Apply\")),\n        React.createElement(\"div\", { className: \"card\" },\n            React.createElement(\"h2\", null, \"Leave History\"),\n            items.length === 0 ? React.createElement(\"p\", { className: \"muted\" }, \"No leave requests.\") : React.createElement(\"div\", { className: \"list\" }, items.map(x => React.createElement(\"div\", { className: \"list-row\", key: x.id },\n                React.createElement(\"div\", null,\n                    React.createElement(\"strong\", null, x.leave_type),\n                    \" \\u00B7 \",\n                    x.leave_date,\n                    x.end_date && x.end_date !== x.leave_date ? ` to ${x.end_date}` : '',\n                    \" \\u00B7 \",\n                    React.createElement(\"strong\", null,\n                        Math.max(1, Math.floor((new Date(`${x.end_date || x.leave_date}T00:00:00Z`) - new Date(`${x.leave_date}T00:00:00Z`)) / 86400000) + 1),\n                        \" Days\"),\n                    React.createElement(\"div\", { className: \"muted\" }, x.reason)),\n                React.createElement(\"div\", { className: \"row-actions\" },\n                    React.createElement(\"span\", { className: `pill ${x.status}` }, x.status),\n                    x.status === 'approved' && x.rollback_status === 'none' && React.createElement(\"button\", { className: \"small-btn\", onClick: () => rollback(x.id) },\n                        React.createElement(RotateCcw, { size: 15 }),\n                        \" Rollback\")))))));\n}\nfunction RecordsTab({ session }) {\n    const [items, setItems] = useState([]);\n    useEffect(() => { api('my_attendance', { session }).then(d => setItems(d.items)).catch(() => { }); }, []);\n    return React.createElement(\"main\", { className: \"content\" },\n        React.createElement(\"div\", { className: \"card\" },\n            React.createElement(\"h2\", null, \"Attendance Records\"),\n            React.createElement(\"div\", { className: \"list\" }, items.map(x => React.createElement(\"div\", { className: \"list-row\", key: x.id },\n                React.createElement(\"div\", null,\n                    React.createElement(\"strong\", null, x.attendance_date),\n                    React.createElement(\"div\", { className: \"muted\" }, x.reason || 'Regular attendance')),\n                React.createElement(\"span\", { className: `pill ${x.status}` }, x.status))))));\n}\nfunction AdminView({ session, flash, fail }) {\n    const [section, setSection] = useState('attendance');\n    return React.createElement(\"main\", { className: \"content\" },\n        React.createElement(\"nav\", { className: \"tabs admin-tabs\" },\n            React.createElement(\"button\", { className: section === 'attendance' ? 'active' : '', onClick: () => setSection('attendance') },\n                React.createElement(ClipboardCheck, { size: 17 }),\n                \" Attendance\"),\n            React.createElement(\"button\", { className: section === 'leave' ? 'active' : '', onClick: () => setSection('leave') },\n                React.createElement(CalendarDays, { size: 17 }),\n                \" Leave\"),\n            React.createElement(\"button\", { className: section === 'users' ? 'active' : '', onClick: () => setSection('users') },\n                React.createElement(UserPlus, { size: 17 }),\n                \" Users\"),\n            React.createElement(\"button\", { className: section === 'sunday' ? 'active' : '', onClick: () => setSection('sunday') },\n                React.createElement(Clock, { size: 17 }),\n                \" Sunday Requests\"),\n            React.createElement(\"button\", { className: section === 'salary' ? 'active' : '', onClick: () => setSection('salary') },\n                React.createElement(Wallet, { size: 17 }),\n                \" Payment\")),\n        section === 'attendance' && React.createElement(AdminAttendance, { session: session, flash: flash, fail: fail }),\n        section === 'leave' && React.createElement(AdminLeave, { session: session, flash: flash, fail: fail }),\n        section === 'users' && React.createElement(AdminUsers, { session: session, flash: flash, fail: fail }),\n        section === 'sunday' && React.createElement(AdminSundayRequests, { session: session, flash: flash, fail: fail }),\n        section === 'salary' && React.createElement(AdminSalary, { session: session, fail: fail }));\n}\nfunction AdminAttendance({ session, flash, fail }) {\n    const [items, setItems] = useState([]);\n    const load = () => api('admin_attendance', { session }).then(d => setItems(d.items)).catch(e => fail(e.message));\n    useEffect(() => { load(); }, []);\n    const review = async (id, approve) => { try {\n        await api('review_attendance', { session, id, approve });\n        flash(approve ? 'Attendance approved.' : 'Attendance rejected as absent.');\n        load();\n    }\n    catch (e) {\n        fail(e.message);\n    } };\n    return React.createElement(\"div\", { className: \"card\" },\n        React.createElement(\"h2\", null, \"Attendance Approval\"),\n        React.createElement(\"div\", { className: \"list\" }, items.map(x => React.createElement(\"div\", { className: \"attendance-review\", key: x.id },\n            React.createElement(\"div\", { className: \"attendance-review-photo\" }, x.selfie_data ? React.createElement(\"img\", { src: x.selfie_data, alt: `Selfie of ${x.user_name}` }) : React.createElement(\"div\", { className: \"camera-placeholder\" },\n                React.createElement(Camera, { size: 28 }),\n                React.createElement(\"span\", null, \"No selfie\"))),\n            React.createElement(\"div\", { className: \"attendance-review-info\" },\n                React.createElement(\"strong\", null, x.user_name),\n                React.createElement(\"div\", { className: \"muted\" },\n                    \"Date: \",\n                    x.attendance_date),\n                React.createElement(\"div\", { className: \"muted\" },\n                    \"Time: \",\n                    x.created_at ? new Date(x.created_at).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }) : '\u2014'),\n                React.createElement(\"div\", { className: \"muted\" },\n                    x.reason || 'Regular attendance',\n                    \" \",\n                    x.latitude ? `\u00b7 GPS ${Number(x.latitude).toFixed(5)}, ${Number(x.longitude).toFixed(5)}` : ''),\n                React.createElement(\"div\", { className: \"review-actions\" },\n                    React.createElement(\"span\", { className: `pill ${x.status}` }, x.status),\n                    x.status === 'pending' && React.createElement(React.Fragment, null,\n                        React.createElement(\"button\", { className: \"approve\", onClick: () => review(x.id, true) },\n                            React.createElement(Check, { size: 15 }),\n                            \" Approve\"),\n                        React.createElement(\"button\", { className: \"reject\", onClick: () => review(x.id, false) },\n                            React.createElement(X, { size: 15 }),\n                            \" Reject\"))))))));\n}\nfunction AdminLeave({ session, flash, fail }) {\n    const [items, setItems] = useState([]);\n    const load = () => api('admin_leaves', { session }).then(d => setItems(d.items)).catch(e => fail(e.message));\n    useEffect(() => { load(); }, []);\n    const review = async (id, approve) => { try {\n        await api('review_leave', { session, id, approve });\n        flash(approve ? 'Leave approved.' : 'Leave rejected.');\n        load();\n    }\n    catch (e) {\n        fail(e.message);\n    } };\n    const rollback = async (id, approve) => { try {\n        await api('review_rollback', { session, id, approve });\n        flash(approve ? 'Rollback approved.' : 'Rollback rejected.');\n        load();\n    }\n    catch (e) {\n        fail(e.message);\n    } };\n    return React.createElement(\"div\", { className: \"card\" },\n        React.createElement(\"h2\", null, \"Leave Approval & Rollback\"),\n        React.createElement(\"div\", { className: \"list\" }, items.map(x => React.createElement(\"div\", { className: \"list-row\", key: x.id },\n            React.createElement(\"div\", null,\n                React.createElement(\"strong\", null, x.user_name),\n                \" \\u00B7 \",\n                x.leave_type,\n                \" \\u00B7 \",\n                x.leave_date,\n                x.end_date && x.end_date !== x.leave_date ? ` to ${x.end_date}` : '',\n                React.createElement(\"div\", { className: \"muted\" }, x.reason)),\n            React.createElement(\"div\", { className: \"row-actions\" },\n                React.createElement(\"span\", { className: `pill ${x.status}` }, x.status),\n                x.status === 'pending' && React.createElement(React.Fragment, null,\n                    React.createElement(\"button\", { className: \"approve\", onClick: () => review(x.id, true) },\n                        React.createElement(Check, { size: 15 })),\n                    React.createElement(\"button\", { className: \"reject\", onClick: () => review(x.id, false) },\n                        React.createElement(X, { size: 15 }))),\n                x.rollback_status === 'pending' && React.createElement(React.Fragment, null,\n                    React.createElement(\"button\", { className: \"small-btn\", onClick: () => rollback(x.id, true) }, \"Approve rollback\"),\n                    React.createElement(\"button\", { className: \"small-btn\", onClick: () => rollback(x.id, false) }, \"Reject rollback\")))))));\n}\nfunction AdminUsers({ session, flash, fail }) {\n    const [items, setItems] = useState([]);\n    const [form, setForm] = useState({ id: '', name: '', password: '', role: 'user', per_day: 0 });\n    const load = () => api('admin_users', { session }).then(d => setItems(d.items)).catch(e => fail(e.message));\n    useEffect(() => { load(); }, []);\n    const create = async (e) => { e.preventDefault(); try {\n        await api('create_user', { session, ...form, per_day: Number(form.per_day || 0) });\n        flash('User created.');\n        setForm({ id: '', name: '', password: '', role: 'user', per_day: 0 });\n        load();\n    }\n    catch (e) {\n        fail(e.message);\n    } };\n    const reset = async (id) => { const p = window.prompt('New password:'); if (!p)\n        return; try {\n        await api('reset_password', { session, id, password: p });\n        flash('Password reset.');\n    }\n    catch (e) {\n        fail(e.message);\n    } };\n    return React.createElement(React.Fragment, null,\n        React.createElement(\"form\", { className: \"card\", onSubmit: create },\n            React.createElement(\"h2\", null, \"Create User\"),\n            React.createElement(\"div\", { className: \"form-grid\" },\n                React.createElement(\"label\", null,\n                    \"User ID\",\n                    React.createElement(\"input\", { value: form.id, onChange: e => setForm({ ...form, id: e.target.value }), required: true })),\n                React.createElement(\"label\", null,\n                    \"Name\",\n                    React.createElement(\"input\", { value: form.name, onChange: e => setForm({ ...form, name: e.target.value }), required: true })),\n                React.createElement(\"label\", null,\n                    \"Initial password\",\n                    React.createElement(\"input\", { type: \"password\", value: form.password, onChange: e => setForm({ ...form, password: e.target.value }), required: true })),\n                React.createElement(\"label\", null,\n                    \"Role\",\n                    React.createElement(\"select\", { value: form.role, onChange: e => setForm({ ...form, role: e.target.value }) },\n                        React.createElement(\"option\", { value: \"user\" }, \"User\"),\n                        React.createElement(\"option\", { value: \"admin\" }, \"Admin\"))),\n                React.createElement(\"label\", null,\n                    \"Per-day salary\",\n                    React.createElement(\"input\", { type: \"number\", min: \"0\", value: form.per_day, onChange: e => setForm({ ...form, per_day: e.target.value }) }))),\n            React.createElement(\"button\", { className: \"primary\" },\n                React.createElement(Plus, { size: 17 }),\n                \" Create user\")),\n        React.createElement(\"div\", { className: \"card\" },\n            React.createElement(\"h2\", null, \"Users\"),\n            React.createElement(\"div\", { className: \"list\" }, items.map(x => React.createElement(\"div\", { className: \"list-row\", key: x.id },\n                React.createElement(\"div\", null,\n                    React.createElement(\"strong\", null, x.name),\n                    React.createElement(\"div\", { className: \"muted\" },\n                        x.id,\n                        \" \\u00B7 \",\n                        x.role,\n                        \" \\u00B7 \\u20B9\",\n                        x.per_day,\n                        \"/day\")),\n                React.createElement(\"button\", { className: \"small-btn\", onClick: () => reset(x.id) },\n                    React.createElement(KeyRound, { size: 15 }),\n                    \" Reset password\"))))));\n}\nfunction SalaryTab({ session }) {\n    const [month, setMonth] = useState(today().slice(0, 7));\n    const [data, setData] = useState(null);\n    const [error, setError] = useState('');\n    const load = () => api('my_salary', { session, month }).then(setData).catch(e => setError(e.message));\n    useEffect(() => { load(); }, [month]);\n    return React.createElement(\"main\", { className: \"content\" },\n        React.createElement(\"div\", { className: \"card\" },\n            React.createElement(\"div\", { className: \"date-lock\" },\n                React.createElement(\"h2\", null, \"Payment / Salary\"),\n                React.createElement(\"input\", { type: \"month\", value: month, onChange: e => setMonth(e.target.value) })),\n            error && React.createElement(\"div\", { className: \"inline-error\" }, error),\n            data && React.createElement(\"div\", { className: \"salary-grid\" }, [['Per-day rate', `\u20b9${data.per_day}`], ['Present days', data.present_days], ['Half days', data.half_days], ['Paid leave', data.paid_leave_days], ['Sunday double-pay days', data.sunday_days], ['Gross salary', `\u20b9${data.gross_salary}`], ['PF', `\u20b9${data.pf_employee}`], ['ESI', `\u20b9${data.esi_employee}`], ['Net take-home', `\u20b9${data.net_salary}`]].map(([a, b]) => React.createElement(\"div\", { className: \"balance card\", key: a },\n                React.createElement(\"span\", null, a),\n                React.createElement(\"strong\", null, b)))),\n            React.createElement(\"p\", { className: \"muted\" }, \"Sunday work is paid at 2\\u00D7 the per-day rate. PF/ESI are calculated using the configured statutory basis.\")));\n}\nfunction AdminSundayRequests({ session, flash, fail }) { const [items, setItems] = useState([]); const load = () => api('admin_sunday_requests', { session }).then(d => setItems(d.items)).catch(e => fail(e.message)); useEffect(() => { load(); }, []); const review = async (id, approve) => { try {\n    await api('review_sunday_request', { session, id, approve });\n    flash(approve ? 'Sunday work approved.' : 'Sunday work rejected.');\n    load();\n}\ncatch (e) {\n    fail(e.message);\n} }; return React.createElement(\"div\", { className: \"card\" },\n    React.createElement(\"h2\", null, \"Sunday Work Requests\"),\n    React.createElement(\"div\", { className: \"list\" }, items.map(x => React.createElement(\"div\", { className: \"list-row\", key: x.id },\n        React.createElement(\"div\", null,\n            React.createElement(\"strong\", null, x.user_name),\n            \" \\u00B7 \",\n            x.work_date,\n            \" \\u00B7 \\u20B9\",\n            x.per_day,\n            \"/day\",\n            React.createElement(\"div\", { className: \"muted\" }, x.reason)),\n        React.createElement(\"div\", { className: \"row-actions\" },\n            React.createElement(\"span\", { className: `pill ${x.status}` }, x.status),\n            x.status === 'pending' && React.createElement(React.Fragment, null,\n                React.createElement(\"button\", { className: \"approve\", onClick: () => review(x.id, true) },\n                    React.createElement(Check, { size: 15 })),\n                React.createElement(\"button\", { className: \"reject\", onClick: () => review(x.id, false) },\n                    React.createElement(X, { size: 15 })))))))); }\nfunction AdminSalary({ session, fail }) { const [month, setMonth] = useState(today().slice(0, 7)); const [items, setItems] = useState([]); useEffect(() => { api('admin_salary', { session, month }).then(d => setItems(d.items)).catch(e => fail(e.message)); }, [month]); return React.createElement(\"div\", { className: \"card\" },\n    React.createElement(\"div\", { className: \"date-lock\" },\n        React.createElement(\"h2\", null, \"Monthly Payment\"),\n        React.createElement(\"input\", { type: \"month\", value: month, onChange: e => setMonth(e.target.value) })),\n    React.createElement(\"div\", { className: \"list\" }, items.map(x => React.createElement(\"div\", { className: \"list-row\", key: x.user_id },\n        React.createElement(\"div\", null,\n            React.createElement(\"strong\", null, x.name),\n            \" \\u00B7 \\u20B9\",\n            x.per_day,\n            \"/day\",\n            React.createElement(\"div\", { className: \"muted\" },\n                \"Present \",\n                x.present_days,\n                \" \\u00B7 Half \",\n                x.half_days,\n                \" \\u00B7 Leave \",\n                x.paid_leave_days,\n                \" \\u00B7 Sunday 2\\u00D7 \",\n                x.sunday_days)),\n        React.createElement(\"div\", null,\n            React.createElement(\"strong\", null,\n                \"Gross \\u20B9\",\n                x.gross_salary),\n            React.createElement(\"div\", { className: \"muted\" },\n                \"PF \\u20B9\",\n                x.pf_employee,\n                \" \\u00B7 ESI \\u20B9\",\n                x.esi_employee,\n                \" \\u00B7 \",\n                React.createElement(\"b\", null,\n                    \"Net \\u20B9\",\n                    x.net_salary))))))); }\ncreateRoot(document.getElementById('root')).render(React.createElement(App, null));\nReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));\n";
const STYLES_CSS = ":root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;color:#0f172a;background:#f1f5f9;line-height:1.45}\n*{box-sizing:border-box}body{margin:0}.app-shell{min-height:100vh}.topbar{background:#0f172a;color:#fff;padding:15px 20px;display:flex;justify-content:space-between;align-items:center}.brand{font-size:20px;font-weight:800}.subbrand{font-size:12px;opacity:.72;margin-top:2px}.content{max-width:980px;margin:0 auto;padding:18px}.tabs{display:flex;gap:6px;background:#fff;border-bottom:1px solid #e2e8f0;padding:8px 12px;position:sticky;top:0;z-index:4}.tabs button{border:0;background:transparent;padding:10px 13px;border-radius:9px;display:flex;gap:7px;align-items:center;color:#64748b;font-weight:700;cursor:pointer}.tabs button.active{background:#e2e8f0;color:#0f172a}.card{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:18px;box-shadow:0 6px 22px rgba(15,23,42,.05);margin-bottom:16px}.hero-card{padding:20px}.date-lock{display:flex;justify-content:space-between;align-items:center}.eyebrow{display:block;font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.08em}.date-lock strong{font-size:24px}.locked{font-size:12px;padding:5px 9px;border-radius:999px;background:#e2e8f0}.muted{color:#64748b;font-size:13px}.location-status{display:flex;align-items:center;gap:8px;padding:11px;border-radius:10px;background:#f8fafc;margin:14px 0}.camera-box{height:360px;background:#0f172a;border-radius:14px;overflow:hidden;display:flex;align-items:center;justify-content:center}.camera-box video,.camera-box img{width:100%;height:100%;object-fit:cover}.camera-placeholder{color:#94a3b8;display:flex;flex-direction:column;align-items:center;gap:8px}.button-row,.row-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}.primary,.secondary,.small-btn,.approve,.reject,.icon-btn{border:0;border-radius:10px;padding:10px 14px;display:inline-flex;align-items:center;gap:7px;font-weight:700;cursor:pointer}.primary{background:#0f172a;color:#fff}.secondary,.small-btn{background:#e2e8f0;color:#0f172a}.approve{background:#dcfce7;color:#166534;padding:8px}.reject{background:#fee2e2;color:#991b1b;padding:8px}.icon-btn{background:#1e293b;color:#fff}.full{width:100%;justify-content:center}.status-box{padding:14px;border-radius:12px;background:#f8fafc;font-weight:700}.balance-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.balance{text-align:center;margin:0}.balance span{display:block;color:#64748b;font-weight:700}.balance strong{display:block;font-size:28px;margin:4px 0}.balance small{color:#94a3b8}.form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:14px}label{display:flex;flex-direction:column;gap:6px;font-weight:700;font-size:13px}input,select,textarea{font:inherit;border:1px solid #cbd5e1;border-radius:9px;padding:10px;background:#fff}textarea{min-height:90px}.wide{grid-column:1/-1}.list{display:flex;flex-direction:column}.list-row{display:flex;justify-content:space-between;gap:14px;align-items:center;padding:13px 0;border-bottom:1px solid #e2e8f0}.list-row:last-child{border-bottom:0}.pill{font-size:12px;font-weight:800;padding:5px 9px;border-radius:999px;background:#e2e8f0}.pill.approved,.pill.present{background:#dcfce7;color:#166534}.pill.pending{background:#fef3c7;color:#92400e}.pill.rejected,.pill.absent{background:#fee2e2;color:#991b1b}.login-wrap{min-height:100vh;display:grid;place-items:center;padding:20px}.login-card{max-width:420px;width:100%}.login-card h1{margin:0}.login-card label{margin:14px 0}.inline-error,.toast{padding:11px 13px;border-radius:10px;margin:10px 0;font-weight:600;font-size:13px}.inline-error,.toast.error{background:#fee2e2;color:#991b1b}.toast.success{background:#dcfce7;color:#166534;position:fixed;right:16px;top:16px;z-index:10;box-shadow:0 10px 30px rgba(0,0,0,.12)}@media(max-width:700px){.content{padding:12px}.balance-grid{grid-template-columns:repeat(2,1fr)}.form-grid{grid-template-columns:1fr}.wide{grid-column:auto}.camera-box{height:300px}.tabs{overflow:auto}.tabs button{white-space:nowrap}.list-row{align-items:flex-start;flex-direction:column}.row-actions{margin-top:0}}\n.salary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:16px}.salary-grid .balance{margin:0}.status-box textarea{display:block;width:100%;margin:12px 0}.status-box .secondary{margin-top:8px}\n";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/attendance') {
      return apiWorker.fetch(request, env, ctx);
    }
    if (url.pathname === '/app.js') {
      return new Response(APP_JS, { headers: { 'content-type': 'application/javascript; charset=UTF-8', 'cache-control': 'no-store' } });
    }
    if (url.pathname === '/styles.css') {
      return new Response(STYLES_CSS, { headers: { 'content-type': 'text/css; charset=UTF-8', 'cache-control': 'no-store' } });
    }
    return new Response(INDEX_HTML, { headers: { 'content-type': 'text/html; charset=UTF-8', 'cache-control': 'no-store' } });
  }
};
