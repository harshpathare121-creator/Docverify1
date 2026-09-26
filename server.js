import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { createWorker } from 'tesseract.js';
import { PDFParse } from 'pdf-parse';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 10000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET || crypto.createHash('sha256').update('connectid-local-demo-secret').digest('hex');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const EMAIL_MODE = String(process.env.EMAIL_MODE || 'auto').trim().toLowerCase();
const RESEND_API_KEY = String(process.env.RESEND_API_KEY || '').trim();
const RESEND_FROM = String(process.env.RESEND_FROM || 'ConnectID <onboarding@resend.dev>').trim();
const RESEND_ENABLED = Boolean(RESEND_API_KEY) && EMAIL_MODE !== 'demo';
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 10);

fs.mkdirSync(DATA_DIR, { recursive: true });
const uploadDir = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'connectid.json');

const emptyDb = () => ({
  meta: { nextUserId: 1, nextPersonNumber: 100245, nextOrgId: 1, nextAdminId: 1, nextDocumentId: 1, nextRequestId: 1, nextNotificationId: 1, nextAuditId: 1, nextOtpId: 1 },
  users: [], organizations: [], admins: [], documents: [], access_requests: [], notifications: [], audit_logs: [], pending_otps: []
});
let db = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) : emptyDb();
db.meta = {...emptyDb().meta, ...(db.meta||{})};
for (const k of ['users','organizations','admins','documents','access_requests','notifications','audit_logs','pending_otps']) if (!Array.isArray(db[k])) db[k]=[];
if (!Number.isInteger(db.meta.nextPersonNumber)) { let max=100244; for (const u of db.users) { const n=Number(String(u.person_id||'').replace('PID-','')); if(Number.isFinite(n)) max=Math.max(max,n); } db.meta.nextPersonNumber=max+1; }
function saveDb(){ const tmp = DB_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8'); fs.renameSync(tmp, DB_FILE); }
function now(){ return new Date().toISOString(); }
function next(type){ const n=db.meta[type]; db.meta[type]=n+1; return n; }
function cleanEmail(x){ return String(x||'').trim().toLowerCase(); }
function gmail(x){ return /^[a-z0-9._%+-]+@gmail\.com$/i.test(String(x||'').trim()); }
function personId(){ const id=`PID-${db.meta.nextPersonNumber}`; db.meta.nextPersonNumber+=1; return id; }
function sign(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn:'7d' }); }
function publicUser(u){ return {id:u.id,person_id:u.person_id,name:u.name,email:u.email,mobile:u.mobile,email_verified:!!u.email_verified,created_at:u.created_at}; }
function sendError(res,status,error){ return res.status(status).json({error, status}); }
function hashValue(value){ return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function sameHash(a,b){ const aa=Buffer.from(String(a||''),'hex'), bb=Buffer.from(String(b||''),'hex'); return aa.length===bb.length && aa.length>0 && crypto.timingSafeEqual(aa,bb); }
function validateName(value){ return /^[A-Za-z][A-Za-z .'-]{1,79}$/.test(String(value||'').trim()); }
function validateMobile(value){ const v=String(value||'').trim(); return !v || /^[0-9+() -]{7,20}$/.test(v); }
function safeOriginalName(value){ return path.basename(String(value||'document')).replace(/[^a-zA-Z0-9._ -]/g,'_').slice(0,120) || 'document'; }
function normalizeOcrText(value){ return String(value||'').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-zA-Z0-9]+/g,' ').toLowerCase().replace(/\s+/g,' ').trim(); }
function levenshtein(a,b){ const prev=Array(b.length+1).fill(0), cur=Array(b.length+1).fill(0); for(let j=0;j<=b.length;j++)prev[j]=j; for(let i=1;i<=a.length;i++){cur[0]=i; for(let j=1;j<=b.length;j++)cur[j]=Math.min(cur[j-1]+1,prev[j]+1,prev[j-1]+(a[i-1]===b[j-1]?0:1)); for(let j=0;j<=b.length;j++)prev[j]=cur[j];} return prev[b.length]; }
function extractOcrName(text){
  const raw=String(text||'').replace(/\r/g,'');
  const labeled=raw.match(/(?:full\s*name|name|student\s*name|applicant\s*name|candidate\s*name|holder\s*name|customer\s*name)\s*[:\-]?\s*([A-Za-z][A-Za-z .\'-]{2,79})/i);
  if(labeled) return labeled[1].trim().split(/\n|\b(?:date|dob|gender|address|id|number|mobile|phone|email)\b/i)[0].trim();
  const lines=raw.split(/\n+/).map(x=>x.trim()).filter(Boolean);
  return lines.find(x=>/^[A-Za-z][A-Za-z .\'-]{2,79}$/.test(x)) || '';
}
function nameMatchesOcr(userName, ocrText){
  const expected=normalizeOcrText(userName);
  const normalized=normalizeOcrText(ocrText);
  if(!expected || !normalized) return {match:false,ocrName:''};
  if(normalized.includes(expected)) return {match:true,ocrName:extractOcrName(ocrText)||userName};
  const candidate=normalizeOcrText(extractOcrName(ocrText));
  if(candidate===expected) return {match:true,ocrName:extractOcrName(ocrText)};
  const a=expected.split(' ').filter(Boolean), b=candidate.split(' ').filter(Boolean);
  if(a.length===b.length && a.length>=2){ const used=new Set(); let ok=true; for(const token of a){ let best=-1,bestD=99; for(let i=0;i<b.length;i++){ if(used.has(i))continue; const d=levenshtein(token,b[i]); const max=Math.max(token.length,b[i].length); if(d/max<0.22 && d<bestD){best=i;bestD=d;} } if(best<0){ok=false;break;} used.add(best);} if(ok) return {match:true,ocrName:extractOcrName(ocrText)}; }
  return {match:false,ocrName:extractOcrName(ocrText)||''};
}
let ocrWorkerPromise=null;
async function getOcrWorker(){ if(!ocrWorkerPromise) ocrWorkerPromise=createWorker('eng'); return ocrWorkerPromise; }
async function extractDocumentText(filePath,mimetype){
  if(mimetype==='application/pdf'){ const parser=new PDFParse({data:fs.readFileSync(filePath)}); try{ const result=await parser.getText({first:3}); return {text:result.text||'',method:'PDF text extraction'}; } finally { await parser.destroy(); } }
  const worker=await getOcrWorker(); const result=await worker.recognize(filePath); return {text:result.data.text||'',method:'Tesseract OCR'};
}
async function sendOtpEmail({to,otp,purpose,name}) {
  if (!RESEND_ENABLED) return {sent:false,mode:'demo'};
  const purposeLabel = purpose === 'register' ? 'Gmail verification' : 'data-access authorization';
  const subject = purpose === 'register' ? 'ConnectID verification code' : 'ConnectID access authorization code';
  const safeName = String(name || 'there').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px;color:#122033">
      <h2 style="margin-bottom:8px">ConnectID</h2>
      <p>Hello ${safeName},</p>
      <p>Your ${purposeLabel} code is:</p>
      <div style="font-size:32px;font-weight:800;letter-spacing:8px;padding:18px;border:1px solid #d8e2ee;border-radius:12px;text-align:center">${otp}</div>
      <p>This code expires in ${OTP_TTL_MINUTES} minutes. If you did not request this code, you can ignore this email.</p>
      <p style="color:#66758a;font-size:12px">ConnectID demo</p>
    </div>`;
  const text = `ConnectID\n\nYour ${purposeLabel} code is: ${otp}\n\nThis code expires in ${OTP_TTL_MINUTES} minutes.`;
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${RESEND_API_KEY}`
    },
    body: JSON.stringify({from:RESEND_FROM,to:[to],subject,html,text})
  });
  let body = {};
  try { body = await response.json(); } catch {}
  if (!response.ok) {
    const detail = body?.message || body?.error || `Resend HTTP ${response.status}`;
    throw new Error(String(detail));
  }
  return {sent:true,mode:'resend',id:body?.id || null};
}

const rateBuckets=new Map();
function rateLimit(key,limit=30,windowMs=60000){ const t=Date.now(); const bucket=rateBuckets.get(key); if(!bucket || t-bucket.start>=windowMs){rateBuckets.set(key,{start:t,count:1});return true;} bucket.count++; return bucket.count<=limit; }
setInterval(()=>{const cutoff=Date.now()-600000;for(const [k,v] of rateBuckets)if(v.start<cutoff)rateBuckets.delete(k)},600000).unref();
function findUserByPerson(pid){ return db.users.find(u=>u.person_id===pid); }
function orgById(id){ return db.organizations.find(o=>o.id===Number(id)); }
function audit(person_id, action, details, organization_id=null){ db.audit_logs.push({id:next('nextAuditId'),person_id,organization_id,action,details,created_at:now()}); saveDb(); }
function notify(person_id,title,message){ db.notifications.push({id:next('nextNotificationId'),person_id,title,message,read:0,created_at:now()}); saveDb(); }
function auth(role){ return (req,res,nextFn)=>{ try{ const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return sendError(res,401,'Authentication required'); const p=jwt.verify(h.slice(7),JWT_SECRET); if(p.role!==role) return sendError(res,403,'Access denied'); req.auth=p; nextFn(); }catch{return sendError(res,401,'Invalid or expired session')} }; }
const personAuth=auth('person'), orgAuth=auth('organization'), adminAuth=auth('admin');

const app=express();
app.disable('x-powered-by');
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  next();
});
app.use(cors({origin:(origin,cb)=>{ const allowed=process.env.PUBLIC_ORIGIN; if(!allowed || !origin) return cb(null,true); return cb(null,origin===allowed); },credentials:false}));
app.use(express.json({limit:'1mb'}));
app.use((req,res,next)=>{ if(req.path.startsWith('/api/auth/') && !rateLimit(`${req.ip}:${req.path}`,12,60000)) return sendError(res,429,'Too many authentication attempts. Please try again shortly.'); next(); });
const upload=multer({dest:path.join(DATA_DIR,'tmp'), limits:{fileSize:10*1024*1024}, fileFilter:(_req,file,cb)=>{ const ok=/^(application\/pdf|image\/(png|jpeg|webp))$/i.test(file.mimetype||''); cb(ok?null:new Error('Only PDF, PNG, JPG, or WEBP files are allowed.'),ok); }});
fs.mkdirSync(path.join(DATA_DIR,'tmp'),{recursive:true});

app.get('/api/health',(_req,res)=>res.json({ok:true,service:'ConnectID API',time:now(),storage:'json',email:{mode:RESEND_ENABLED?'resend':'demo',configured:Boolean(RESEND_API_KEY),fromConfigured:Boolean(RESEND_FROM)}}));

app.post('/api/auth/register',async(req,res)=>{
  try{
    const name=String(req.body.name||'').trim(), email=cleanEmail(req.body.email), mobile=String(req.body.mobile||'').trim(), password=String(req.body.password||'');
    if(!validateName(name)||!gmail(email)||!validateMobile(mobile)||password.length<8) return sendError(res,400,'Enter a valid name, Gmail address, mobile number, and password of at least 8 characters.');
    if(db.users.some(u=>u.email===email)) return sendError(res,409,'An account with this Gmail already exists.');
    const user={id:next('nextUserId'),person_id:personId(),name,email,mobile,password_hash:await bcrypt.hash(password,10),email_verified:0,created_at:now()};
    const otp=String(crypto.randomInt(100000,1000000));
    const pending={id:next('nextOtpId'),email,otp_hash:hashValue(otp),attempts:0,expires_at:Date.now()+OTP_TTL_MINUTES*60000,purpose:'register'};
    const delivery=await sendOtpEmail({to:email,otp,purpose:'register',name});
    db.users.push(user);
    db.pending_otps=db.pending_otps.filter(x=>!(x.email===email&&x.purpose==='register'));
    db.pending_otps.push(pending);
    saveDb();
    res.json({ok:true,email,personId:user.person_id,delivery:delivery.mode,demoOtp:delivery.mode==='demo'?otp:undefined});
  }catch(e){
    console.error('Registration email failed:', e);
    return sendError(res,502,`Unable to send verification email. ${e.message || 'Please check the Resend configuration.'}`);
  }
});

app.post('/api/auth/verify-email',(req,res)=>{
  const email=cleanEmail(req.body.email), otp=String(req.body.otp||'');
  const row=[...db.pending_otps].reverse().find(x=>x.email===email&&x.purpose==='register');
  if(!row||Date.now()>row.expires_at) return sendError(res,400,'Invalid or expired OTP.');
  row.attempts=Number(row.attempts||0)+1;
  if(row.attempts>5){ db.pending_otps=db.pending_otps.filter(x=>x.id!==row.id); saveDb(); return sendError(res,429,'Too many OTP attempts. Request a new verification code.'); }
  if(!sameHash(hashValue(otp),row.otp_hash)){ saveDb(); return sendError(res,400,'Invalid or expired OTP.'); }
  const user=db.users.find(u=>u.email===email); if(!user)return sendError(res,404,'Account not found');
  user.email_verified=1; db.pending_otps=db.pending_otps.filter(x=>x.id!==row.id); saveDb();
  audit(user.person_id,'EMAIL_VERIFIED','Gmail verification completed');
  res.json({token:sign({role:'person',sub:user.id,personId:user.person_id}),user:publicUser(user)});
});

app.post('/api/auth/login',async(req,res)=>{
  const email=cleanEmail(req.body.email), password=String(req.body.password||''); const u=db.users.find(x=>x.email===email);
  if(!u||!(await bcrypt.compare(password,u.password_hash))) return sendError(res,401,'Invalid Gmail or password.');
  if(!u.email_verified) return sendError(res,403,'Please verify your Gmail first.');
  res.json({token:sign({role:'person',sub:u.id,personId:u.person_id}),user:publicUser(u)});
});
app.post('/api/org/login',async(req,res)=>{ const code=String(req.body.orgCode||'').trim(), password=String(req.body.password||''); const o=db.organizations.find(x=>x.org_code===code); if(!o||!(await bcrypt.compare(password,o.password_hash)))return sendError(res,401,'Invalid organization credentials.'); res.json({token:sign({role:'organization',sub:o.id,orgCode:o.org_code}),organization:{id:o.id,code:o.org_code,name:o.name,type:o.type}}); });
app.post('/api/admin/login',async(req,res)=>{ const code=String(req.body.adminCode||'').trim(), password=String(req.body.password||''); const a=db.admins.find(x=>x.admin_code===code); if(!a||!(await bcrypt.compare(password,a.password_hash)))return sendError(res,401,'Invalid admin credentials.'); res.json({token:sign({role:'admin',sub:a.id}),admin:{id:a.id,code:a.admin_code,name:a.name}}); });
app.get('/api/org/me',orgAuth,(req,res)=>{const o=orgById(req.auth.sub); if(!o)return sendError(res,404,'Organization not found'); res.json({id:o.id,code:o.org_code,name:o.name,type:o.type});});
app.get('/api/admin/me',adminAuth,(req,res)=>{const a=db.admins.find(x=>x.id===Number(req.auth.sub)); if(!a)return sendError(res,404,'Admin not found'); res.json({id:a.id,code:a.admin_code,name:a.name});});

app.get('/api/me',personAuth,(req,res)=>{ const u=db.users.find(x=>x.id===Number(req.auth.sub)); if(!u)return sendError(res,404,'User not found'); res.json(publicUser(u)); });
app.get('/api/documents',personAuth,(req,res)=>res.json(db.documents.filter(d=>d.user_id===Number(req.auth.sub)).sort((a,b)=>b.id-a.id).map(d=>({...d,extracted:d.extracted_json?JSON.parse(d.extracted_json):null}))));
app.post('/api/documents',personAuth,upload.single('document'),async(req,res)=>{
  if(!req.file)return sendError(res,400,'Choose a document file.');
  const u=db.users.find(x=>x.id===Number(req.auth.sub));
  if(!u){try{fs.unlinkSync(req.file.path)}catch{} return sendError(res,404,'User not found.');}
  const originalName=safeOriginalName(req.file.originalname);
  const documentType=String(req.body.documentType||'Other').trim();
  const allowedDocumentTypes=['Identity Document','Address Proof','Education Document','Other'];
  if(!allowedDocumentTypes.includes(documentType)){ try{fs.unlinkSync(req.file.path)}catch{} return sendError(res,400,'Invalid document type.'); }
  try{
    const ocr=await extractDocumentText(req.file.path,req.file.mimetype);
    const check=nameMatchesOcr(u.name,ocr.text);
    if(!check.match){
      try{fs.unlinkSync(req.file.path)}catch{}
      audit(u.person_id,'DOCUMENT_REJECTED',`Rejected ${originalName}: OCR name mismatch`);
      return sendError(res,422,`Invalid file: the name on the document does not match your profile name. OCR detected: ${check.ocrName||'No readable name'}.`);
    }
    const safe=crypto.randomUUID()+path.extname(originalName).toLowerCase();
    const finalPath=path.join(uploadDir,safe); fs.renameSync(req.file.path,finalPath);
    const extracted={fullName:check.ocrName||u.name,personId:u.person_id,documentType,fileName:originalName,fileSize:req.file.size,ocrStatus:'Verified',ocrMethod:ocr.method,ocrText:ocr.text.slice(0,4000),nameMatch:true,note:'Document name matched the registered profile name.'};
    db.documents.push({id:next('nextDocumentId'),user_id:u.id,original_name:originalName,stored_name:safe,document_type:documentType,extracted_json:JSON.stringify(extracted),created_at:now()}); saveDb(); audit(u.person_id,'DOCUMENT_UPLOADED',`Uploaded and OCR-verified ${originalName}`); res.json({ok:true,ocr:{fullName:extracted.fullName,status:'Verified',method:ocr.method}});
  }catch(e){ console.error('OCR upload failed',e); try{fs.unlinkSync(req.file.path)}catch{} return sendError(res,422,'Unable to read the document for OCR. Please upload a clear JPG, PNG, WEBP, or a text-readable PDF.'); }
});

app.post('/api/access-requests',orgAuth,(req,res)=>{
  const personId=String(req.body.personId||'').trim(), requestedData=Array.isArray(req.body.requestedData)?req.body.requestedData:[], purpose=String(req.body.purpose||'').trim(), duration=String(req.body.duration||'').trim();
  if(!rateLimit(`org-request:${req.auth.sub}`,20,60000)) return sendError(res,429,'Too many access requests. Please try again shortly.');
  const allowedData=['Full Name','Email','Mobile','Identity Document']; const cleanRequested=[...new Set(requestedData.map(x=>String(x).trim()).filter(x=>allowedData.includes(x)))]; const allowedDurations=['24 hours','7 days','30 days']; if(!cleanRequested.length||cleanRequested.length!==requestedData.length)return sendError(res,400,'Invalid data selection.'); if(!allowedDurations.includes(duration))return sendError(res,400,'Invalid access duration.'); if(purpose.length<5||purpose.length>300)return sendError(res,400,'Purpose must be between 5 and 300 characters.'); const person=findUserByPerson(personId); if(!person||!person.email_verified)return sendError(res,404,'Verified Person ID not found.'); if(!purpose)return sendError(res,400,'Enter a purpose.')
  const r={id:next('nextRequestId'),person_id:personId,organization_id:Number(req.auth.sub),requested_data:JSON.stringify(cleanRequested),purpose,duration,status:'Pending',otp_hash:null,otp_attempts:0,otp_expires_at:null,created_at:now(),approved_at:null,granted_at:null,revoked_at:null}; db.access_requests.push(r); const o=orgById(req.auth.sub); notify(personId,'New access request',`${o.name} requested: ${cleanRequested.join(', ')}. Purpose: ${purpose}.`); audit(personId,'ACCESS_REQUESTED',`Requested ${cleanRequested.join(', ')}`,o.id); res.json({ok:true,requestId:r.id});
});
function requestView(r){ const o=orgById(r.organization_id); return {...r,organization_name:o?.name||'Unknown',organization_type:o?.type||'',requestedData:JSON.parse(r.requested_data)}; }
app.get('/api/access-requests',personAuth,(req,res)=>res.json(db.access_requests.filter(r=>r.person_id===req.auth.personId).sort((a,b)=>b.id-a.id).map(requestView)));
app.get('/api/org/access-requests',orgAuth,(req,res)=>res.json(db.access_requests.filter(r=>r.organization_id===Number(req.auth.sub)).sort((a,b)=>b.id-a.id).map(r=>{const u=findUserByPerson(r.person_id);return {...r,person_name:u?.name||'',person_id:r.person_id,requestedData:JSON.parse(r.requested_data)}})));
app.post('/api/access-requests/:id/decision',personAuth,async(req,res)=>{
  const r=db.access_requests.find(x=>x.id===Number(req.params.id)&&x.person_id===req.auth.personId); if(!r)return sendError(res,404,'Request not found');
  const decision=req.body.decision; const o=orgById(r.organization_id); if(r.status!=='Pending')return sendError(res,400,'This request is no longer pending.');
  if(decision==='deny'){r.status='Denied'; saveDb(); audit(r.person_id,'ACCESS_DENIED',`Denied request #${r.id}`,r.organization_id); notify(r.person_id,'Access request denied',`You denied ${o?.name||'the organization'} request #${r.id}.`); return res.json({ok:true,status:r.status});}
  if(decision!=='approve')return sendError(res,400,'Invalid decision');
  const user=findUserByPerson(r.person_id); if(!user)return sendError(res,404,'User not found');
  const otp=String(crypto.randomInt(100000,1000000));
  try{
    const delivery=await sendOtpEmail({to:user.email,otp,purpose:'access',name:user.name});
    r.status='Awaiting OTP'; r.otp_hash=hashValue(otp); r.otp_attempts=0; r.otp_expires_at=Date.now()+OTP_TTL_MINUTES*60000; r.approved_at=now();
    saveDb(); audit(r.person_id,'ACCESS_APPROVED',`Approved request #${r.id}`,r.organization_id); notify(r.person_id,'Access approved',`${o?.name||'Organization'} may complete OTP authorization for request #${r.id}.`);
    res.json({ok:true,status:r.status,delivery:delivery.mode,demoOtp:delivery.mode==='demo'?otp:undefined});
  }catch(e){
    console.error('Access OTP email failed:', e);
    return sendError(res,502,`Unable to send access authorization email. ${e.message || 'Please check the Resend configuration.'}`);
  }
});
app.post('/api/access-requests/:id/authorize',orgAuth,(req,res)=>{
  if(!rateLimit(`org-authorize:${req.auth.sub}`,30,60000)) return sendError(res,429,'Too many authorization attempts. Please try again shortly.');
  const r=db.access_requests.find(x=>x.id===Number(req.params.id)&&x.organization_id===Number(req.auth.sub)); if(!r)return sendError(res,404,'Request not found'); const otp=String(req.body.otp||'');
  if(r.status!=='Awaiting OTP')return sendError(res,400,'This request is not awaiting OTP.');
  if(Date.now()>r.otp_expires_at){r.status='Expired';r.otp_hash=null;saveDb();return sendError(res,400,'Approval OTP has expired. The person must approve the request again.');}
  r.otp_attempts=Number(r.otp_attempts||0)+1;
  if(r.otp_attempts>5){r.status='Expired';r.otp_hash=null;saveDb();return sendError(res,429,'Too many OTP attempts. The person must approve the request again.');}
  if(!sameHash(hashValue(otp),r.otp_hash)){saveDb();return sendError(res,400,'Invalid or expired OTP.');}
  r.status='Granted';r.granted_at=now();saveDb();audit(r.person_id,'ACCESS_GRANTED',`Organization completed OTP for request #${r.id}`,r.organization_id);notify(r.person_id,'Data access granted',`${orgById(r.organization_id)?.name||'Organization'} now has approved access for request #${r.id}.`);res.json({ok:true,status:r.status});
});
app.post('/api/access-requests/:id/revoke',personAuth,(req,res)=>{const r=db.access_requests.find(x=>x.id===Number(req.params.id)&&x.person_id===req.auth.personId);if(!r)return sendError(res,404,'Request not found');if(r.status!=='Granted')return sendError(res,400,'Only granted access can be revoked.');r.status='Revoked';r.revoked_at=now();saveDb();audit(r.person_id,'ACCESS_REVOKED',`Revoked request #${r.id}`,r.organization_id);notify(r.person_id,'Access revoked',`Access for request #${r.id} was revoked.`);res.json({ok:true});});
app.get('/api/notifications',personAuth,(req,res)=>res.json(db.notifications.filter(n=>n.person_id===req.auth.personId).sort((a,b)=>b.id-a.id)));
app.post('/api/notifications/:id/read',personAuth,(req,res)=>{const n=db.notifications.find(x=>x.id===Number(req.params.id)&&x.person_id===req.auth.personId);if(!n)return sendError(res,404,'Notification not found');n.read=1;saveDb();res.json({ok:true});});
app.get('/api/audit',personAuth,(req,res)=>res.json(db.audit_logs.filter(a=>a.person_id===req.auth.personId).sort((a,b)=>b.id-a.id).map(a=>({...a,organization_name:orgById(a.organization_id)?.name||null}))));
app.get('/api/granted-data/:requestId',orgAuth,(req,res)=>{const r=db.access_requests.find(x=>x.id===Number(req.params.requestId)&&x.organization_id===Number(req.auth.sub));if(!r||r.status!=='Granted')return sendError(res,404,'Granted request not found');const u=findUserByPerson(r.person_id);if(!u)return sendError(res,404,'User not found');const requested=JSON.parse(r.requested_data);const access={personId:u.person_id,name:u.name};if(requested.includes('Email'))access.email=u.email;if(requested.includes('Mobile'))access.mobile=u.mobile;const documents=requested.includes('Identity Document')?db.documents.filter(d=>d.user_id===u.id).sort((a,b)=>b.id-a.id).map(d=>({id:d.id,name:d.original_name,type:d.document_type,created_at:d.created_at,extracted:d.extracted_json?JSON.parse(d.extracted_json):null})):[];res.json({access,purpose:r.purpose,duration:r.duration,documents});});
app.get('/api/granted-data/:requestId/documents/:documentId/download',orgAuth,(req,res)=>{const r=db.access_requests.find(x=>x.id===Number(req.params.requestId)&&x.organization_id===Number(req.auth.sub));if(!r||r.status!=='Granted')return sendError(res,404,'Granted request not found');const requested=JSON.parse(r.requested_data);if(!requested.includes('Identity Document'))return sendError(res,403,'Identity document access was not granted.');const u=findUserByPerson(r.person_id);const d=db.documents.find(x=>x.id===Number(req.params.documentId)&&x.user_id===u?.id);if(!d)return sendError(res,404,'Document not found');const fp=path.join(uploadDir,d.stored_name);if(!fs.existsSync(fp))return sendError(res,404,'Stored document file is missing');res.download(fp,d.original_name);});

app.get('/api/admin/overview',adminAuth,(req,res)=>res.json({users:db.users.length,verifiedUsers:db.users.filter(u=>u.email_verified).length,organizations:db.organizations.length,documents:db.documents.length,requests:db.access_requests.length,pending:db.access_requests.filter(r=>r.status==='Pending').length,granted:db.access_requests.filter(r=>r.status==='Granted').length}));
app.get('/api/admin/users',adminAuth,(req,res)=>res.json(db.users.map(u=>({...publicUser(u),documents:db.documents.filter(d=>d.user_id===u.id).map(d=>({...d,extracted:d.extracted_json?JSON.parse(d.extracted_json):null})),accessRequests:db.access_requests.filter(r=>r.person_id===u.person_id).map(requestView),notifications:db.notifications.filter(n=>n.person_id===u.person_id),audit:db.audit_logs.filter(a=>a.person_id===u.person_id).map(a=>({...a,organization_name:orgById(a.organization_id)?.name||null}))})).sort((a,b)=>b.id-a.id)));
app.get('/api/admin/documents/:id/download',adminAuth,(req,res)=>{const d=db.documents.find(x=>x.id===Number(req.params.id));if(!d)return sendError(res,404,'Document not found');const fp=path.join(uploadDir,d.stored_name);if(!fs.existsSync(fp))return sendError(res,404,'Stored document file is missing');res.download(fp,d.original_name);});
app.get('/api/admin/organizations',adminAuth,(req,res)=>res.json(db.organizations.map(o=>({id:o.id,org_code:o.org_code,name:o.name,type:o.type,created_at:o.created_at}))));
app.get('/api/admin/audit',adminAuth,(req,res)=>res.json(db.audit_logs.slice().sort((a,b)=>b.id-a.id).slice(0,500).map(a=>({...a,person_name:findUserByPerson(a.person_id)?.name||null,organization_name:orgById(a.organization_id)?.name||null}))));

async function seed(){
  if(!db.organizations.length){ db.organizations.push({id:next('nextOrgId'),org_code:'HOSP001',name:'CityCare Hospital',type:'Hospital',password_hash:await bcrypt.hash('hospital123',10),created_at:now()}); }
  if(!db.admins.length){ db.admins.push({id:next('nextAdminId'),admin_code:'ADMIN001',name:'ConnectID Demo Admin',password_hash:await bcrypt.hash('admin12345',10),created_at:now()}); }
  saveDb();
}
await seed();
app.use(express.static(__dirname));
app.get('*',(req,res,nextFn)=>{if(req.path.startsWith('/api/'))return nextFn();res.sendFile(path.join(__dirname,'index.html'));});
app.use((err,_req,res,_next)=>{ console.error(err); if(err instanceof multer.MulterError) return sendError(res,400,err.code==='LIMIT_FILE_SIZE'?'File exceeds the 10 MB limit.':'Upload failed.'); return sendError(res,400,err.message||'Request failed.'); });
if(IS_PRODUCTION && !process.env.JWT_SECRET) console.warn('JWT_SECRET is not set; using the built-in demo fallback secret.');
app.listen(PORT,'0.0.0.0',()=>console.log(`ConnectID API listening on ${PORT}; data=${DATA_DIR}`));
