import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {fileURLToPath} from 'url';

const app=express();
app.use(express.json({limit:'30mb'}));
const root=path.dirname(fileURLToPath(import.meta.url));
const storage=process.env.STORAGE_PATH||'D:\\SAST_Report_System\\records';
fs.mkdirSync(storage,{recursive:true});
fs.mkdirSync(path.join(storage,'backups'),{recursive:true});
fs.mkdirSync(path.join(storage,'attachments'),{recursive:true});
const dbFile=path.join(storage,'sast_records.json');
let db=fs.existsSync(dbFile)?JSON.parse(fs.readFileSync(dbFile,'utf8')):{next_filing:1,next_template_report:101,next_template_form:101,templates:[],officers:[],records:[],ranks:[]};
db.templates??=[];db.officers??=[];db.records??=[];db.ranks??=[];db.admins??=[];db.officers.forEach(o=>{if(!o.role)o.role=o.admin?'admin':'standard';if(o.role==='admin')o.admin=true});
db.next_filing??=1;db.next_template_report??=101;db.next_template_form??=101;
const defaultRanks=['Cadet','Trooper','Trooper First Class','Senior Trooper','Corporal','Sergeant','Lieutenant','Captain','Major','Lieutenant Colonel','Colonel']; if(!Array.isArray(db.ranks)||!db.ranks.length) db.ranks=defaultRanks; db.ranks=db.ranks.filter(r=>!['Deputy Commissioner','Commissioner'].includes(r));
const nextDoc=type=>{let n=type==='report'?db.next_template_report++:db.next_template_form++;return '1ST-'+(type==='report'?'R':'F')+'-'+n};
const patrol={id:1,title:'SAST Daily Patrol Log',record_type:'form',doc_no:'1ST-F-101',fields:[],active:true};
const templateCatalog=[
{title:'Society Fund Reimbursement Form',type:'form',sections:[
['Member Information',[['Name','name','text'],['Rank','rank','rank'],['Callsign / Unit','unit','text'],['Division','division','text'],['Date','date','date']]],
['Purchase Information',[['Item(s) Purchased','items_purchased','textarea'],['Reason for Purchase','reason','textarea'],['Department Purpose','department_purpose','textarea'],['Date Purchased','date_purchased','date'],['Total Amount','total_amount','money'],['Payment Method','payment_method','text'],['Store / Vendor','vendor','text']]],
['Proof of Purchase',[['Receipt Attached','receipt_attached','choice','Yes|No'],['Receipt / Transaction Number','receipt_number','text']]],
['Reimbursement',[['Amount Requested','amount_requested','money'],['Requested Payment Method','requested_payment_method','text'],['Additional Notes','additional_notes','textarea']]],
['Approval',[['Supervisor Name','supervisor_name','officer'],['Supervisor Rank','supervisor_rank','rank'],['Approved','approved','choice','Yes|No'],['Supervisor Signature','supervisor_signature','signature'],['Date','approval_date','date']]],
['Society Fund Treasurer',[['Reviewed By','reviewed_by','officer'],['Amount Approved','amount_approved','money'],['Payment Issued','payment_issued','choice','Yes|No'],['Date Paid','date_paid','date'],['Signature','treasurer_signature','signature']]]]},
{title:'Incident Report',type:'report',sections:[
['Incident Information',[['Report Number','report_number','text'],['Date','date','date'],['Time','time','time'],['Location','location','text'],['Postal','postal','text'],['Incident Type','incident_type','text'],['Call / Dispatch Number','dispatch_number','text']]],
['Reporting Trooper',[['Name','name','officer'],['Rank','rank','rank'],['Callsign','callsign','text'],['Division','division','text']]],
['Involved Persons',[['Subject 1 Name','subject1_name','text'],['DOB / Age','subject1_age','text'],['Description','subject1_description','textarea'],['Vehicle','subject1_vehicle','text'],['Plate','subject1_plate','text'],['Additional Subjects','additional_subjects','textarea'],['Role in Incident','additional_role','text']]],
['Assisting Personnel',[['Trooper','assisting_trooper','officer'],['Agency','assisting_agency','text'],['Unit','assisting_unit','text']]],
['Incident Narrative',[['Narrative','narrative','textarea']]],
['Evidence',[['Body Camera','body_camera','choice','Yes|No'],['Dash Camera','dash_camera','choice','Yes|No'],['Photographs','photographs','choice','Yes|No'],['Video / CCTV','video_cctv','choice','Yes|No'],['Other Evidence','other_evidence','textarea']]],
['Disposition',[['Arrest Made','arrest_made','choice','Yes|No'],['Citation Issued','citation_issued','choice','Yes|No'],['Subject Released','subject_released','choice','Yes|No'],['EMS Required','ems_required','choice','Yes|No'],['Other','disposition_other','textarea']]],
['Supervisor Review',[['Supervisor','supervisor','officer'],['Rank','supervisor_rank','rank'],['Reviewed','reviewed','choice','Yes|No'],['Comments','comments','textarea']]]]},
{title:'Taser Deployment Report',type:'report',sections:[
['Deployment Information',[['Report Number','report_number','text'],['Date','date','date'],['Time','time','time'],['Location','location','text'],['Postal','postal','text'],['Trooper','trooper','officer'],['Rank','rank','rank'],['Unit','unit','text'],['Taser Serial Number','taser_serial','text']]],
['Subject',[['Name','subject_name','text'],['Description','description','textarea'],['Reason for Contact','reason_contact','textarea']]],
['Circumstances',[['Reason Taser Was Deployed','reason_deployed','textarea'],['Commands Given Before Deployment','commands_before','textarea'],['Subject\'s Actions','subject_actions','textarea'],['Threat Level','threat_level','text']]],
['Deployment',[['Number of Taser Cycles','cycles','number'],['Duration','duration','text'],['Cartridge Used','cartridge_used','text'],['Effective','effective','choice','Yes|No'],['Probe Contact','probe_contact','choice','Yes|No'],['Drive Stun','drive_stun','choice','Yes|No']]],
['After Deployment',[['Subject Restrained','restrained','choice','Yes|No'],['EMS Requested','ems_requested','choice','Yes|No'],['Medical Evaluation','medical_evaluation','textarea'],['Probes Removed By','probes_removed_by','text'],['Evidence Collected','evidence_collected','textarea']]],
['Narrative',[['Narrative','narrative','textarea']]],
['Supervisor Review',[['Supervisor','supervisor','officer'],['Rank','supervisor_rank','rank'],['Reviewed','reviewed','choice','Yes|No'],['Findings / Comments','findings','textarea']]]]},
{title:'Use of Force Report',type:'report',sections:[
['Incident Information',[['Report Number','report_number','text'],['Date','date','date'],['Time','time','time'],['Location','location','text'],['Postal','postal','text'],['Reporting Trooper','trooper','officer'],['Rank','rank','rank'],['Unit','unit','text']]],
['Subject Information',[['Name','subject_name','text'],['Description','description','textarea'],['Vehicle','vehicle','text'],['Plate','plate','text']]],
['Type of Force Used',[['Force Types','force_types','multi','Verbal Commands|Physical Control|Handcuffs|Taser|Baton|Less-Lethal|Firearm Displayed|Firearm Discharged|Other']]],
['Reason for Force',[['Subject\'s Actions','subject_actions','textarea'],['Threat Presented','threat_presented','textarea'],['Commands Given','commands_given','textarea'],['De-escalation Attempted','deescalation','textarea']]],
['Force Used',[['Describe exactly what force was used and why','force_description','textarea']]],
['Injuries',[['Trooper Injured','trooper_injured','choice','Yes|No'],['Subject Injured','subject_injured','choice','Yes|No'],['Civilian Injured','civilian_injured','choice','Yes|No'],['EMS Called','ems_called','choice','Yes|No']]],
['Evidence',[['BWC','bwc','text'],['Dashcam','dashcam','text'],['Photos','photos','text'],['Witnesses','witnesses','textarea'],['Other Evidence','other_evidence','textarea']]],
['Supervisor Review',[['Supervisor','supervisor','officer'],['Rank','supervisor_rank','rank'],['Review Date','review_date','date'],['Findings','findings','textarea'],['Corrective Action Required','corrective_action','choice','Yes|No']]]]},
{title:'Firearm Discharge Report',type:'report',sections:[
['Incident Information',[['Report Number','report_number','text'],['Date','date','date'],['Time','time','time'],['Location','location','text'],['Postal','postal','text'],['Trooper','trooper','officer'],['Rank','rank','rank'],['Unit','unit','text']]],
['Firearm Information',[['Firearm Type','firearm_type','text'],['Make / Model','make_model','text'],['Serial Number','serial_number','text'],['Ammunition Type','ammo_type','text'],['Rounds Loaded','rounds_loaded','number'],['Rounds Fired','rounds_fired','number']]],
['Circumstances',[['Reason Firearm Was Drawn','reason_drawn','textarea'],['Reason Firearm Was Discharged','reason_discharged','textarea'],['Threat Presented','threat_presented','textarea'],['Commands Given','commands_given','textarea'],['De-escalation Attempted','deescalation','textarea']]],
['Shots Fired',[['Number of Shots','shots','number'],['Approximate Distance','distance','text'],['Direction of Fire','direction','text'],['Target','target','text'],['Was Anyone Struck?','anyone_struck','choice','Yes|No']]],
['Injuries',[['Suspect','suspect_injury','textarea'],['Trooper','trooper_injury','textarea'],['Civilian','civilian_injury','textarea'],['Fatality','fatality','choice','Yes|No'],['EMS Responded','ems_responded','choice','Yes|No']]],
['Scene / Evidence',[['Weapon Recovered','weapon_recovered','choice','Yes|No'],['Shell Casings Recovered','casings','choice','Yes|No'],['BWC Available','bwc_available','choice','Yes|No'],['Photographs Taken','photos_taken','choice','Yes|No'],['Witnesses','witnesses','textarea']]],
['Narrative',[['Narrative','narrative','textarea']]],
['Supervisor Review',[['Supervisor','supervisor','officer'],['Command Staff Notified','command_notified','text'],['Weapon Secured','weapon_secured','text'],['Firearm Placed Out of Service','out_of_service','choice','Yes|No'],['Review Complete','review_complete','choice','Yes|No']]]]},
{title:'K-9 Subdivision Report',type:'report',sections:[
['K-9 Information',[['Handler','handler','officer'],['K-9 Name','k9_name','text'],['K-9 Number','k9_number','text'],['Date','date','date'],['Time','time','time'],['Location','location','text'],['Call Type','call_type','text']]],
['K-9 Activity',[['Activity','activity','multi','Tracking|Article Search|Narcotics Detection|Vehicle Search|Building Search|Suspect Search|Apprehension|Demonstration|Other']]],
['Deployment',[['Deployment Reason','deployment_reason','textarea'],['Results','results','textarea']]],
['Evidence Located',[['Item','item','text'],['Location Found','location_found','text'],['Evidence Number','evidence_number','text']]],
['Injuries',[['K-9','k9_injury','textarea'],['Handler','handler_injury','textarea'],['Subject','subject_injury','textarea']]],
['Additional Information',[['Additional Information','additional','textarea']]],
['Supervisor Review',[['Supervisor','supervisor','officer'],['Comments','comments','textarea']]]]},
{title:'SWAT Subdivision Report',type:'report',sections:[
['Operation Information',[['Operation Number','operation_number','text'],['Date','date','date'],['Time','time','time'],['Location','location','text'],['Postal','postal','text'],['Operation Commander','commander','officer']]],
['Mission Type',[['Mission Type','mission_type','multi','High-Risk Warrant|Hostage Situation|Barricaded Subject|Armed Subject|High-Risk Arrest|Other']]],
['SWAT Personnel',[['Team Leader','team_leader','officer'],['Operators','operators','textarea'],['Negotiator','negotiator','officer'],['Medic','medic','officer'],['K-9','k9','officer'],['Supporting Agencies','supporting_agencies','textarea']]],
['Operation Summary',[['Summary','summary','textarea']]],
['Subject Information',[['Name','subject_name','text'],['Known Weapons','known_weapons','textarea'],['Charges / Reason for Operation','charges','textarea']]],
['Outcome',[['Outcome','outcome','multi','Arrest|Surrender|Medical Transport|Escape|Fatality|Other']]],
['Force Used',[['Taser','taser','text'],['Less-Lethal','less_lethal','text'],['Firearm Discharge','firearm_discharge','text'],['Other','force_other','textarea']]],
['Evidence',[['Evidence','evidence','textarea']]],
['Command Review',[['Commander','review_commander','officer'],['Supervisor','supervisor','officer'],['Final Disposition','final_disposition','textarea']]]]},
{title:'NARCOTICS Subdivision Report',type:'report',sections:[
['Case Information',[['Case Number','case_number','text'],['Investigator','investigator','officer'],['Rank','rank','rank'],['Date Opened','date_opened','date'],['Location','location','text']]],
['Investigation Type',[['Investigation Type','investigation_type','multi','Traffic Stop|Search Warrant|Buy/Bust|Surveillance|Informant|Vehicle Search|Residence Search|Other']]],
['Subject Information',[['Name','subject_name','text'],['Vehicle','vehicle','text'],['Plate','plate','text'],['Address','address','text']]],
['Suspected Drugs',[['Substance','substance','text'],['Estimated Quantity','quantity','text'],['Packaging','packaging','text'],['Suspected Intent','intent','text'],['Other Contraband','contraband','textarea']]],
['Investigation Narrative',[['Narrative','narrative','textarea']]],
['Evidence',[['Evidence 1 Description','evidence1','textarea'],['Evidence 1 Location Found','evidence1_location','text'],['Evidence 1 Number','evidence1_number','text'],['Evidence 2 Description','evidence2','textarea'],['Evidence 2 Location Found','evidence2_location','text'],['Evidence 2 Number','evidence2_number','text'],['Evidence 3 Description','evidence3','textarea'],['Evidence 3 Location Found','evidence3_location','text'],['Evidence 3 Number','evidence3_number','text']]],
['Disposition',[['Disposition','disposition','multi','Arrest|Citation|Investigation Continuing|Evidence Submitted|No Further Action']]],
['Supervisor',[['Name','supervisor','officer'],['Rank','supervisor_rank','rank'],['Approval','approval','choice','Approved|Not Approved']]]]},
{title:'TRAFFIC Division Report',type:'report',sections:[
['Stop Information',[['Report Number','report_number','text'],['Date','date','date'],['Time','time','time'],['Location','location','text'],['Postal','postal','text'],['Trooper','trooper','officer'],['Unit','unit','text']]],
['Driver',[['Name','driver_name','text'],['License Status','license_status','text'],['Vehicle','vehicle','text'],['Plate','plate','text'],['Registration','registration','text']]],
['Violation',[['Violations','violations','multi','Speeding|Reckless Driving|Careless Driving|No Insurance|Suspended/Revoked License|Expired Registration|Illegal Modification|Other']]],
['Details',[['Posted Speed','posted_speed','number'],['Observed Speed','observed_speed','number'],['Method of Speed Detection','speed_method','text'],['Other Violations','other_violations','textarea']]],
['Enforcement',[['Enforcement Action','enforcement','multi','Warning|Citation|Arrest|Vehicle Impounded|Vehicle Released']]],
['Narrative',[['Narrative','narrative','textarea']]]]},
{title:'MBU Subdivision Report',type:'report',sections:[
['Patrol Information',[['Trooper','trooper','officer'],['Rank','rank','rank'],['MBU Unit','unit','text'],['Date','date','date'],['Shift','shift','text'],['Patrol Area','patrol_area','text']]],
['Activity',[['Activity','activity','multi','Traffic Enforcement|Pursuit Assistance|Escort|Traffic Control|Scene Security|Criminal Enforcement|Other']]],
['Incident Information',[['Location','location','text'],['Postal','postal','text'],['Call Type','call_type','text'],['Assisting Units','assisting_units','textarea']]],
['Narrative',[['Narrative','narrative','textarea']]],
['Enforcement / Outcome',[['Arrests','arrests','number'],['Citations','citations','number'],['Vehicle Impounds','impounds','number'],['Other Actions','other_actions','textarea']]],
['Supervisor',[['Name','supervisor','officer'],['Rank','supervisor_rank','rank'],['Review','review','textarea']]]]},
{title:'Equipment Loss Report',type:'report',sections:[
['Employee Information',[['Name','name','officer'],['Rank','rank','rank'],['Unit','unit','text'],['Division','division','text'],['Date','date','date']]],
['Lost Equipment',[['Equipment Items','equipment_items','table','Item|Serial/ID|Quantity|Last Known Location']]],
['Circumstances',[['Date / Time Last Seen','last_seen','datetime'],['Location','location','text'],['Circumstances of Loss','circumstances','textarea'],['Was Equipment Stolen?','stolen','choice','Yes|No'],['Was Equipment Damaged?','damaged','choice','Yes|No']]],
['Actions Taken',[['Search Conducted','search_conducted','choice','Yes|No'],['Supervisor Notified','supervisor_notified','choice','Yes|No'],['Evidence / Report Number','evidence_number','text'],['Replacement Requested','replacement_requested','choice','Yes|No']]],
['Narrative',[['Narrative','narrative','textarea']]],
['Supervisor Review',[['Supervisor','supervisor','officer'],['Rank','supervisor_rank','rank'],['Findings','findings','textarea'],['Approved Replacement','approved_replacement','choice','Yes|No']]]]},
{title:'Armory Sign-In / Sign-Out',type:'form',sections:[
['Personnel',[['Name','name','officer'],['Rank','rank','rank'],['Unit','unit','text'],['Date','date','date']]],
['Equipment Log',[['Equipment Transactions','equipment_transactions','table','Time|Item|Serial/ID|Qty|Action|Condition|Signature']]],
['Equipment Status',[['Equipment Condition When Issued','condition_issued','textarea'],['Equipment Condition When Returned','condition_returned','textarea'],['Missing / Damaged Items','missing_damaged','textarea'],['Notes','notes','textarea']]],
['Armorer',[['Armorer','armorer','officer'],['Signature','signature','signature']]]]},
{title:'Vehicle Sign-Out Sheet',type:'form',sections:[
['Vehicle Information',[['Vehicle Number','vehicle_number','text'],['Unit / Callsign','unit','text'],['Vehicle Type','vehicle_type','text'],['Plate','plate','text'],['Date','date','date']]],
['Vehicle Sign-Out',[['Sign-Out Entries','sign_out_entries','table','Time Out|Trooper|Unit|Vehicle|Mileage|Fuel|Condition']]],
['Vehicle Return',[['Return Entries','return_entries','table','Time In|Trooper|Mileage|Fuel|Damage|Equipment Missing']]],
['Vehicle Inspection',[['Exterior Damage','exterior_damage','choice','None|Yes'],['Interior Damage','interior_damage','choice','None|Yes'],['Emergency Equipment Working','emergency_equipment','choice','Yes|No'],['Radio Working','radio_working','choice','Yes|No'],['Lights / Sirens Working','lights_sirens','choice','Yes|No'],['Weapon Rack / Equipment Secure','equipment_secure','choice','Yes|No'],['Damage / Missing Equipment Description','damage_description','textarea']]],
['Review',[['Trooper Signature','trooper_signature','signature'],['Fleet / Command Review','command_review','textarea'],['Date','review_date','date']]]]}
];
function catalogFields(item){return item.sections.flatMap(([section,fs])=>fs.map(f=>({section,label:f[0],key:f[1],type:f[2],options:f[3]?f[3].split('|'):[],required:true})));}
if(!db.templates.length)db.templates=[patrol];
for(const item of templateCatalog){
 const existing=db.templates.find(t=>t.title===item.title);
 if(!existing)db.templates.push({id:Date.now()+Math.floor(Math.random()*100000),title:item.title,record_type:item.type,doc_no:nextDoc(item.type),fields:catalogFields(item),active:true,created_at:new Date().toISOString()});
 else if(!existing.fields?.length)existing.fields=catalogFields(item);
}
fs.writeFileSync(dbFile,JSON.stringify(db,null,2));

const save=()=>{const raw=JSON.stringify(db,null,2);fs.writeFileSync(dbFile,raw);fs.writeFileSync(path.join(storage,'backups','sast_records_'+Date.now()+'.json'),raw)};
const filing=()=>String(db.next_filing++).padStart(4,'0');
const clean=v=>String(v??'').trim();
const secret=process.env.SESSION_SECRET||'CHANGE-ME-SAST-SESSION-SECRET';
const isLocal=req=>['localhost','127.0.0.1','::1'].includes((req.hostname||'').toLowerCase());
const b64=s=>Buffer.from(s).toString('base64url');
const unb64=s=>Buffer.from(s,'base64url').toString();
const sign=s=>crypto.createHmac('sha256',secret).update(s).digest('base64url');
function cookie(res,name,value,maxAge=60*60*8){res.setHeader('Set-Cookie',name+'='+value+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+maxAge)};
function clearCookie(res,name){res.setHeader('Set-Cookie',name+'=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')};
function parseCookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i).trim(),x.slice(i+1)]}))}
function makeSession(u){const payload=b64(JSON.stringify({id:u.id,username:u.username,avatar:u.avatar||null,iat:Date.now()}));return payload+'.'+sign(payload)}
function readSession(req){try{const v=parseCookies(req).sast_session||'';const [p,s]=v.split('.');if(!p||!s||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(sign(p))))return null;const u=JSON.parse(unb64(p));if(Date.now()-u.iat>1000*60*60*8)return null;return u}catch{return null}}
function currentUser(req){if(isLocal(req))return {local:true,admin:true,supervisor:true,role:'admin',id:'localhost',username:'Local Administrator'};const s=readSession(req);if(!s)return null;const o=db.officers.find(x=>x.active!==false&&clean(x.discord_id)===clean(s.id));if(!o)return null;const role=o.role||(o.admin?'admin':'standard');const admin=role==='admin'||db.admins.includes(clean(s.id));const supervisor=role==='supervisor'||admin;return {local:false,admin,supervisor,role,id:s.id,username:s.username,officer:o}}
function requireAuth(req,res,next){const u=currentUser(req);if(!u)return res.status(401).json({error:'Discord sign-in required'});req.user=u;next()}
function requireAdmin(req,res,next){const u=currentUser(req);if(!u||!u.admin)return res.status(403).json({error:'Administrator access required'});req.user=u;next()}
function requireSupervisor(req,res,next){const u=currentUser(req);if(!u||!u.supervisor)return res.status(403).json({error:'Supervisor or Administrator access required'});req.user=u;next()}
function roleName(u){return u?.local?'admin':(u?.role||'standard')}
function requireLocal(req,res,next){return requireAdmin(req,res,next)}
app.get('/auth/login',(req,res)=>{
  if(isLocal(req))return res.redirect('/');
  const id=process.env.DISCORD_CLIENT_ID,redirect=process.env.DISCORD_REDIRECT_URI||'http://localhost:3050/auth/callback';
  if(!id)return res.status(503).send('Discord login is not configured. Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET and DISCORD_REDIRECT_URI.');
  const state=crypto.randomBytes(24).toString('hex');cookie(res,'sast_oauth_state',b64(JSON.stringify({state,exp:Date.now()+600000})),600);
  const u='https://discord.com/oauth2/authorize?client_id='+encodeURIComponent(id)+'&redirect_uri='+encodeURIComponent(redirect)+'&response_type=code&scope=identify&state='+encodeURIComponent(state);
  res.redirect(u);
});
app.get('/auth/callback',async(req,res)=>{
  try{
    const c=parseCookies(req),st=c.sast_oauth_state?JSON.parse(unb64(c.sast_oauth_state)):null;
    if(!st||st.state!==req.query.state||st.exp<Date.now())return res.status(400).send('Invalid or expired Discord login state.');
    const params=new URLSearchParams({client_id:process.env.DISCORD_CLIENT_ID||'',client_secret:process.env.DISCORD_CLIENT_SECRET||'',grant_type:'authorization_code',code:String(req.query.code||''),redirect_uri:process.env.DISCORD_REDIRECT_URI||'http://localhost:3050/auth/callback'});
    const tok=await fetch('https://discord.com/api/oauth2/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:params});
    if(!tok.ok)throw Error('Discord token exchange failed');
    const td=await tok.json(),me=await fetch('https://discord.com/api/users/@me',{headers:{Authorization:'Bearer '+td.access_token}});
    if(!me.ok)throw Error('Discord identity lookup failed');
    const u=await me.json(),o=db.officers.find(x=>x.active!==false&&clean(x.discord_id)===clean(u.id));
    clearCookie(res,'sast_oauth_state');
    if(!o)return res.status(403).send('Your Discord account is not linked to an active SAST officer record. Ask a local administrator to add your Discord ID.');
    cookie(res,'sast_session',makeSession(u),60*60*8);res.redirect('/');
  }catch(e){res.status(500).send('Discord sign-in failed: '+escHtml(e.message))}
});
app.get('/auth/logout',(req,res)=>{clearCookie(res,'sast_session');res.redirect('/')});
function escHtml(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
app.get('/api/me',(req,res)=>{const u=currentUser(req);res.json(u?{authenticated:true,local:!!u.local,admin:!!u.admin,supervisor:!!u.supervisor,role:u.role||'admin',username:u.username,officer:u.officer||null}:{authenticated:false,loginConfigured:!!process.env.DISCORD_CLIENT_ID})});
app.use(express.static(path.join(root,'public')));
app.get('/api/templates',requireAuth,(q,s)=>s.json(db.templates.filter(x=>x.active!==false)));
app.get('/api/officers',requireAuth,(q,s)=>s.json(db.officers.filter(x=>x.active!==false)));
app.get('/api/records',requireAuth,(q,s)=>s.json(db.records.slice().reverse().map(({data,...r})=>r)));
app.get('/api/records/:filing',requireAuth,(q,s)=>{const r=db.records.find(x=>x.filing_no===q.params.filing);r?s.json(r):s.status(404).json({error:'Record not found'})});
app.get('/api/records/search/:q',requireAuth,(q,s)=>{const x=decodeURIComponent(q.params.q).toLowerCase();s.json(db.records.filter(r=>(r.filing_no+' '+r.doc_no+' '+r.title+' '+r.author).toLowerCase().includes(x)).slice(0,25).map(({data,...r})=>r))});
app.get('/api/records/lookup/:q',requireAuth,(q,s)=>{const x=decodeURIComponent(q.params.q).toLowerCase();s.json(db.records.filter(r=>(r.filing_no+' '+r.doc_no+' '+r.title).toLowerCase().includes(x)).slice(0,10).map(r=>({filing_no:r.filing_no,doc_no:r.doc_no,title:r.title,author:r.author}))) });
app.get('/api/attachments/:filing/:file',requireAuth,(q,s)=>{const r=db.records.find(x=>x.filing_no===q.params.filing),name=path.basename(q.params.file);if(!r||!(r.attachments||[]).some(a=>a.file===name))return s.status(404).end();const p=path.join(storage,'attachments',q.params.filing,name);if(!fs.existsSync(p))return s.status(404).end();s.sendFile(p)});
app.get('/api/ranks',requireAuth,(q,s)=>s.json(db.ranks));
app.post('/api/officers',requireAdmin,(q,s)=>{const b=q.body;if(!clean(b.first_name)||!clean(b.last_name))return s.status(400).json({error:'First and last name are required'});const role=['standard','supervisor','admin'].includes(b.role)?b.role:(b.admin?'admin':'standard');const o={id:Date.now(),first_name:clean(b.first_name),last_name:clean(b.last_name),rank:clean(b.rank),unit:clean(b.unit),division:clean(b.division),discord_id:clean(b.discord_id),role,admin:role==='admin',active:true};db.officers.push(o);save();s.json(o)});
app.delete('/api/officers/:id',requireAdmin,(q,s)=>{const o=db.officers.find(x=>x.id===Number(q.params.id));if(!o)return s.status(404).json({error:'Officer not found'});o.active=false;save();s.json({ok:true})});
app.put('/api/officers/:id',requireAdmin,(q,s)=>{const o=db.officers.find(x=>x.id===Number(q.params.id)&&x.active!==false);if(!o)return s.status(404).json({error:'Officer not found'});const b=q.body;if(!clean(b.first_name)||!clean(b.last_name))return s.status(400).json({error:'First and last name are required'});const role=['standard','supervisor','admin'].includes(b.role)?b.role:(b.admin?'admin':'standard');Object.assign(o,{first_name:clean(b.first_name),last_name:clean(b.last_name),rank:clean(b.rank),unit:clean(b.unit),division:clean(b.division),discord_id:clean(b.discord_id),role,admin:role==='admin'});save();s.json(o)});
app.post('/api/ranks',requireAdmin,(q,s)=>{const r=clean(q.body.rank);if(!r)return s.status(400).json({error:'Rank is required'});if(db.ranks.includes(r))return s.status(409).json({error:'Rank already exists'});db.ranks.push(r);save();s.json(r)});
app.delete('/api/ranks/:rank',requireAdmin,(q,s)=>{const r=decodeURIComponent(q.params.rank);db.ranks=db.ranks.filter(x=>x!==r);save();s.json({ok:true})});
app.post('/api/templates',requireAdmin,(q,s)=>{const b=q.body,type=b.record_type==='report'?'report':'form';if(!clean(b.title))return s.status(400).json({error:'Template title is required'});const t={id:Date.now(),title:clean(b.title),record_type:type,doc_no:nextDoc(type),fields:Array.isArray(b.fields)?b.fields:[],active:true,created_at:new Date().toISOString()};db.templates.push(t);save();s.json(t)});
app.put('/api/templates/:id',requireAdmin,(q,s)=>{const t=db.templates.find(x=>x.id===Number(q.params.id));if(!t)return s.status(404).json({error:'Template not found'});Object.assign(t,{title:clean(q.body.title)||t.title,fields:Array.isArray(q.body.fields)?q.body.fields:t.fields,active:q.body.active!==false});save();s.json(t)});
app.put('/api/records/:filing',requireSupervisor,(q,s)=>{const r=db.records.find(x=>x.filing_no===q.params.filing);if(!r)return s.status(404).json({error:'Record not found'});const incoming=q.body?.data&&typeof q.body.data==='object'?q.body.data:{};const before=JSON.parse(JSON.stringify(r.data||{}));const changes=[];const keys=new Set([...Object.keys(before),...Object.keys(incoming)]);for(const key of keys){const a=JSON.stringify(before[key]??'');const b=JSON.stringify(incoming[key]??'');if(a!==b)changes.push({field:key,from:before[key]??'',to:incoming[key]??''})}r.data={...before,...incoming};if(q.body?.sign){r.data.supervisor_signed=true;r.data.supervisor_signature=clean(q.body.sign.signature);r.data.supervisor_signature_font=clean(q.body.sign.font)||'Segoe Print';r.data.supervisor_signed_at=new Date().toISOString();r.status='Supervisor Signed';changes.push({field:'supervisor_signature',from:'',to:r.data.supervisor_signature})}const editor=q.user?.officer?`${q.user.officer.first_name} ${q.user.officer.last_name}`:q.user?.username||'Local Administrator';r.edit_log??=[];r.edit_log.push({id:Date.now(),timestamp:new Date().toISOString(),editor,role:roleName(q.user),changes,action:q.body?.sign?'Supervisor signature / record edit':'Record edit'});save();fs.writeFileSync(path.join(storage,r.filing_no+'_'+r.doc_no+'.json'),JSON.stringify(r,null,2));s.json(r)});
app.post('/api/records',requireAuth,(q,s)=>{const b=q.body,t=db.templates.find(x=>x.id===Number(b.template_id));if(!t||!clean(b.author))return s.status(400).json({error:'Template and reporting officer are required'});if(!currentUser(q).local){const me=q.user.officer,norm=x=>clean(x).toLowerCase();if(norm(b.author)!==norm(me.first_name+' '+me.last_name))return s.status(403).json({error:'You may only file reports under your own officer name.'})}
 const data=b.data&&typeof b.data==='object'?b.data:{};const refs=Array.isArray(data.cross_references)?data.cross_references:[];if(refs.length>10)return s.status(400).json({error:'A record may contain at most 10 cross-references.'});const resolved=[];for(const ref of refs){const doc=clean(ref.doc_no).toUpperCase(),fil=clean(ref.filing_no);if(!doc&&!fil)continue;const target=db.records.find(x=>x.doc_no.toUpperCase()===doc&&x.filing_no===fil);if(!target)return s.status(400).json({error:'Cross-reference not found: '+doc+' / '+fil});resolved.push({doc_no:target.doc_no,filing_no:target.filing_no,title:target.title})}data.cross_references=resolved;
 const incoming=Array.isArray(b.attachments)?b.attachments:[];if(incoming.length>10)return s.status(400).json({error:'A record may contain at most 10 photos.'});let total=0;const cleanAttachments=[];const no=filing();const attachmentDir=path.join(storage,'attachments',no);fs.mkdirSync(attachmentDir,{recursive:true});for(let i=0;i<incoming.length;i++){const a=incoming[i]||{},m=String(a.data||'').match(/^data:(image\/(?:jpeg|png|gif|webp));base64,(.+)$/);if(!m)return s.status(400).json({error:'Only JPEG, PNG, GIF, and WebP photos are allowed.'});const buf=Buffer.from(m[2],'base64');if(!buf.length||buf.length>5*1024*1024)return s.status(400).json({error:'Each photo must be 5 MB or smaller.'});total+=buf.length;if(total>15*1024*1024)return s.status(400).json({error:'All photos together must be 15 MB or smaller.'});const ext={jpeg:'jpg',png:'png',gif:'gif',webp:'webp'}[m[1].split('/')[1]];const file='photo_'+String(i+1).padStart(2,'0')+'.'+ext;fs.writeFileSync(path.join(attachmentDir,file),buf);cleanAttachments.push({file,original_name:clean(a.name).slice(0,160)||file,mime:m[1],size:buf.length})}data.attachments=cleanAttachments;
 const r={id:Date.now(),filing_no:no,doc_no:t.doc_no,title:t.title,record_type:t.record_type,template_id:t.id,author:clean(b.author),data,status:'Filed',created_at:new Date().toISOString(),attachments:cleanAttachments,edit_log:[]};db.records.push(r);save();fs.writeFileSync(path.join(storage,no+'_'+t.doc_no+'.json'),JSON.stringify(r,null,2));notify(r);s.json(r)});
async function notify(r,action='Filed'){const u=process.env.DISCORD_WEBHOOK_URL;if(!u)return;try{const payload={embeds:[{title:'SAST Record '+action,description:r.title,fields:[{name:'Filing',value:r.filing_no,inline:true},{name:'Document',value:r.doc_no,inline:true},{name:'Author',value:r.author,inline:true},{name:'Status',value:r.status||action,inline:true}],timestamp:new Date().toISOString()}]};const form=new FormData();form.append('payload_json',JSON.stringify(payload));form.append('files[0]',new Blob([JSON.stringify(r,null,2)],{type:'application/json'}),'SAST_'+r.filing_no+'_'+r.doc_no+'.json');await fetch(u,{method:'POST',body:form})}catch(e){console.error('Discord webhook error:',e.message)}}
const port=process.env.PORT||3050;
app.listen(port,()=>console.log('SAST system running on http://localhost:'+port));