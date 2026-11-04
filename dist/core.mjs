export function parseCSV(text) {
  text=text.replace(/^\uFEFF/,''); const rows=[]; let row=[],cell='',quoted=false;
  for(let i=0;i<text.length;i++){const c=text[i];if(c==='"'){if(quoted&&text[i+1]==='"'){cell+='"';i++;}else quoted=!quoted;}else if(c===','&&!quoted){row.push(cell);cell='';}else if((c==='\n'||c==='\r')&&!quoted){if(c==='\r'&&text[i+1]==='\n')i++;row.push(cell);if(row.some(v=>v.trim()))rows.push(row);row=[];cell='';}else cell+=c;}
  if(quoted)throw Error('CSV contains an unclosed quote.');row.push(cell);if(row.some(v=>v.trim()))rows.push(row);return rows;
}
export function records(text){
 const rows=parseCSV(text);if(!rows.length)return [];
 const headers=rows[0].map(x=>x.trim().toLowerCase().replace(/[_-]+/g,' '));
 const emailIndex=headers.findIndex(h=>/^(e ?mail( address)?|emailaddress)$/.test(h));
 const statusIndex=headers.findIndex(h=>/^(imported status|hunter status)$/.test(h))>=0?headers.findIndex(h=>/^(imported status|hunter status)$/.test(h)):headers.findIndex(h=>/^(status|result|verification status|email status)$/.test(h));
 if(emailIndex<0&&rows[0].length>1&&!rows[0].some(x=>x.includes('@')))throw Error('Include an email or email address column in your CSV.');
 return (emailIndex>=0?rows.slice(1):rows).map(r=>({email:(r[emailIndex>=0?emailIndex:0]||'').trim(),provider:emailIndex>=0&&statusIndex>=0?(r[statusIndex]||'').trim():''}));
}
const disposable=new Set(['mailinator.com','guerrillamail.com','guerrillamail.net','10minutemail.com','tempmail.com','yopmail.com','throwawaymail.com','getnada.com','dispostable.com','trashmail.com']);
const roles=new Set(['info','sales','contact','support','admin','office','hello','enquiries','inquiries','team','billing','accounts','noreply','no-reply']);
export function syntax(email){
 if(!email||email.length>254)return {ok:false,reason:'Missing or overly long address'};
 const p=email.split('@');if(p.length!==2)return {ok:false,reason:'Expected one @ symbol'};
 const [local,domain]=p;
 if(!/^[\x21-\x7e]+$/.test(email)||local.startsWith('"'))return {ok:false,unknown:true,reason:'International or quoted address requires specialist verification'};
 if(local.length>64||!local||local.startsWith('.')||local.endsWith('.')||local.includes('..')||!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local))return {ok:false,reason:'Invalid local part'};
 if(domain.length>253||!domain.includes('.')||!domain.split('.').every(l=>l.length>0&&l.length<=63&&/^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(l)))return {ok:false,reason:'Invalid domain format'};
 return {ok:true,domain:domain.toLowerCase(),role:roles.has(local.toLowerCase()),disposable:disposable.has(domain.toLowerCase())};
}
export function assessDNS(mx,a=[],aaaa=[]){
 if(mx.Status===3)return {status:'invalid',reason:'Domain does not exist',hosts:[]};
 if(mx.Status!==0)return {status:'unknown',reason:'DNS lookup failed; retry later',hosts:[]};
 const entries=(mx.Answer||[]).filter(x=>x.type===15).map(x=>{const p=x.data.trim().split(/\s+/);return {priority:Number(p[0]),host:p[1]};});
 if(entries.some(x=>x.host==='.'))return {status:'invalid',reason:'Null MX: domain explicitly does not accept mail',hosts:[]};
 if(entries.length)return {status:'passed',reason:'Mail servers found; mailbox unconfirmed',hosts:entries.sort((a,b)=>a.priority-b.priority).map(x=>x.host.replace(/\.$/,''))};
 if([a,aaaa].some(r=>r.Status===0&&(r.Answer||[]).some(x=>x.type===1||x.type===28)))return {status:'passed',reason:'Address-record mail fallback; mailbox unconfirmed',hosts:[],fallback:true};
 if([a,aaaa].some(r=>r.Status!==0&&r.Status!==3))return {status:'unknown',reason:'Address-record lookup failed; retry later',hosts:[]};
 return {status:'invalid',reason:'No MX or address records for mail delivery',hosts:[]};
}
export {interpretSMTP as smtpOutcome} from './evidence.mjs';
export function csvCell(v){let s=String(v??'');if(/^[\s]*[=+@-]/.test(s))s="'"+s;return '"'+s.replaceAll('"','""')+'"';}
