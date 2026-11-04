export const RULESET='2026-11-03.4';
const nonexistent=r=>r?.code===550&&/\b5\.1\.1\b|no such (user|mailbox)|user unknown|unknown (user|recipient)|recipient (not found|does not exist)|mailbox (not found|does not exist)/i.test(r.text);
function microsoftMissing(r,host){return r?.code===550&&/(^|\.)mail\.protection\.outlook\.com$/i.test(host)&&/^550 5\.4\.1 Recipient address rejected: Access denied\./im.test(r.text)&&/https:\/\/aka\.ms\/EXOSmtpErrors\b/i.test(r.text);}
function consumerMissing(r,host){return r?.code===550&&/(^|\.)olc\.protection\.outlook\.com$/i.test(host)&&/^550 5\.5\.0 Requested action not taken: mailbox unavailable \(S2017062302\)/im.test(r.text);}
function googleDisabled(r,host){return r?.code===550&&/(^|\.)(google\.com|googlemail\.com)$/i.test(host)&&/\b5\.2\.1\b/.test(r.text)&&/https:\/\/support\.google\.com\/mail\/\?p=DisabledUser\b/i.test(r.text);}
export function diagnostics(m){
 const text=m.reason||'';
 if(/HELO|EHLO/i.test(text))return 'Greeting rejected. Configure MAILCHECK_HELO with your own legitimate fully qualified mail hostname. Do not invent an identity.';
 if(m.failure_kind==='tls'||/certificate|TLS|SSL|altnames|key too/i.test(text))return 'TLS verification failed. The receiving administrator must fix the certificate or TLS configuration. Certificate validation remains enabled.';
 if(m.recipient_status==='temporary'||m.retryable)return 'Temporary or network failure. Retry only after the cooldown; a timeout is not evidence of an invalid inbox.';
 if(m.recipient_status==='blocked'||m.failure_kind==='policy')return 'Server policy or sender reputation blocked the check. Mailbox existence is unresolved.';
 if(m.status==='catch-all')return 'Server accepted random recipients. Individual inbox existence remains uncertain.';
 return '';
}
export function interpretSMTP(real,random,{host=''}={}){
 const base={ruleset:RULESET,recipient_status:'unknown',catchall_status:'not_tested',retryable:false,rule:'unclassified'};
 const out=(status,reason,extra={})=>({...base,status,reason,...extra});
 if(googleDisabled(real,host))return out('rejected','Google reports this mailbox is inactive or disabled',{recipient_status:'rejected',rule:'google-disabled-5.2.1'});
 if(microsoftMissing(real,host)||consumerMissing(real,host))return out('rejected','Microsoft rejected the recipient at directory/address lookup; inspect for stale or misconfigured recipient records',{recipient_status:'rejected',rule:'microsoft-recipient-rejected'});
 if(nonexistent(real))return out('rejected','Server explicitly reports a nonexistent recipient',{recipient_status:'rejected',rule:'smtp-5.1.1'});
 if(real.code!==250)return out('unknown','Recipient not confirmed: '+real.text,{recipient_status:real.code>=400&&real.code<500?'temporary':real.code===251?'forwarded':'blocked',retryable:real.code>=400&&real.code<500,rule:'recipient-inconclusive'});
 base.recipient_status='accepted';base.catchall_status='unknown';
 if(random?.code===250)return out('catch-all','Real and random recipients accepted; individual inbox existence remains uncertain',{catchall_status:'yes',rule:'random-recipient-accepted'});
 if(nonexistent(random))return out('accepted','Recipient accepted; random recipient explicitly nonexistent. Delivery is not guaranteed.',{catchall_status:'no',rule:'random-5.1.1'});
 if(consumerMissing(random,host))return out('accepted','Recipient accepted; Microsoft consumer address lookup rejected the random recipient. Delivery is not guaranteed.',{catchall_status:'no',rule:'microsoft-consumer-random-5.5.0'});
 if(microsoftMissing(random,host))return out('accepted','Recipient accepted; Microsoft directory blocking rejected the random recipient. Delivery is not guaranteed.',{catchall_status:'no',rule:'microsoft-dbeb-random-5.4.1'});
 return out('accepted-unconfirmed','Recipient accepted; catch-all status remains inconclusive',{catchall_status:'unknown',retryable:!!random&&random.code>=400&&random.code<500,rule:'accepted-catchall-inconclusive'});
}
export function classifyFailure(error){
 const message=error.message||String(error),code=error.code||'';
 const certificate=/CERT|TLS|SSL|certificate|altnames/i.test(code+' '+message);
 const temporary=/\b4\d\d[ -]/.test(message);
 const policy=!temporary&&/5\.7\.|policy|SpamBot|Sender rejected|HELO|EHLO/i.test(message);
 const connection=!certificate&&!policy&&(/ECONNREFUSED|ECONNRESET|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH/.test(code+' '+message)||/SMTP timed out|SMTP connection closed/.test(message));
 
 return {status:'unknown',recipient_status:'unknown',catchall_status:'not_tested',check_failed:true,retryable:!certificate&&(connection||temporary),failure_kind:certificate?'tls':policy?'policy':connection?'connection':temporary?'temporary':'infrastructure',reason:message,ruleset:RULESET};
}
export function retryDue(r,now=Date.now()){return !!r.mailbox?.retryable&&!r.suppressed&&!r.duplicate&&(r.attempts||1)<3&&Date.parse(r.retry_at||'')<=now;}
export function assessOutcome(r,events){
 const checked=Date.parse(r.checked||'');const eligible=events.filter(e=>e.email.toLowerCase()===r.email.toLowerCase()&&Number.isFinite(checked)&&Date.parse(e.observed_at)>=checked);
 if(!eligible.length)return {outcome:'unobserved',assessment:'No subsequent delivery evidence'};
 const kinds=new Set(eligible.map(e=>e.outcome));
 if(kinds.has('hard_bounce')&&(kinds.has('reply')||kinds.has('delivered')))return {outcome:'conflicting',assessment:'Conflicting observed outcomes; inspect individual attempts'};
 const outcome=kinds.has('hard_bounce')?'hard_bounce':kinds.has('reply')?'reply':kinds.has('delivered')?'delivered':'soft_bounce';
 return {outcome,assessment:outcome==='hard_bounce'&&r.mailbox?.status==='accepted'?'SMTP acceptance followed by hard bounce':outcome==='reply'||outcome==='delivered'?'Observed delivery evidence':outcome==='soft_bounce'?'Temporary delivery failure; inbox existence unresolved':'Observed hard bounce'};
}
export function csvObjects(text,parseCSV){const data=parseCSV(text);if(!data.length)return [];const h=data.shift().map(x=>x.trim().toLowerCase());return data.map(r=>Object.fromEntries(h.map((v,i)=>[v,r[i]||''])));}
export function savedMailbox(r){
 if(!r.recipient_reply&&['not checked','not_checked',''].includes(r.mailbox_status||''))return {status:'not checked',recipient_status:'not checked',catchall_status:'not_tested',reason:r.evidence||'No mailbox probe performed',ruleset:RULESET,retryable:false};
 const real=r.recipient_reply&&{code:Number(r.recipient_reply.slice(0,3)),text:r.recipient_reply};const random=r.catchall_reply&&{code:Number(r.catchall_reply.slice(0,3)),text:r.catchall_reply};
 let history=[];try{const parsed=JSON.parse(r.attempt_history||'[]');if(Array.isArray(parsed))history=parsed;}catch{}
 const metadata={host:r.smtp_host,encrypted:r.smtp_tls==='true',recipient_reply:r.recipient_reply,catchall_reply:r.catchall_reply,attempt_history:history};
 return {...(real?interpretSMTP(real,random||undefined,{host:r.smtp_host}):classifyFailure(Error(r.evidence||'No saved recipient response'))),...metadata};
}
