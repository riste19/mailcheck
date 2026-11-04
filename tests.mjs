import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {parseCSV,records,syntax,assessDNS,smtpOutcome,csvCell} from './dist/core.mjs';
import {probe,publicIP} from './smtp.mjs';
import {queryDNS} from './dist/dns-query.mjs';
import {createCachedResolver} from './dns-cache.mjs';
test('bulk DNS cache respects TTL and does not cache failures',async()=>{
 let calls=0,time=0;const lookup=createCachedResolver(async()=>{calls++;return {Status:0,Answer:[{TTL:2,type:1,data:'8.8.8.8'}]};},()=>time);
 await lookup('A.test','A');await lookup('a.test','A');assert.equal(calls,1);time=2001;await lookup('a.test','A');assert.equal(calls,2);
 let failed=0;const broken=createCachedResolver(async()=>{failed++;throw Error('offline');});await assert.rejects(()=>broken('a.test','A'));await assert.rejects(()=>broken('a.test','A'));assert.equal(failed,2);
});
test('Microsoft consumer lookup is recognized only for the documented host and response signature',()=>{
 const real={code:250,text:'250 OK'},random={code:550,text:'550 5.5.0 Requested action not taken: mailbox unavailable (S2017062302). [outlook.com]'};
 assert.equal(interpretSMTP(real,random,{host:'hotmail-com.olc.protection.outlook.com'}).status,'accepted');
 assert.equal(interpretSMTP(real,random,{host:'other.example'}).status,'accepted-unconfirmed');
 assert.equal(interpretSMTP(random,undefined,{host:'hotmail-com.olc.protection.outlook.com'}).status,'rejected');
 assert.equal(interpretSMTP(real,{code:550,text:'550 5.5.0 mailbox unavailable'},{host:'hotmail-com.olc.protection.outlook.com'}).status,'accepted-unconfirmed');
});
test('Google disabled recipients are rejected only with provider and support signature',()=>{
 const real={code:550,text:'550-5.2.1 The email account is inactive\n550 5.2.1 https://support.google.com/mail/?p=DisabledUser - gsmtp'};
 assert.equal(interpretSMTP(real,undefined,{host:'gmail-smtp-in.l.google.com'}).rule,'google-disabled-5.2.1');
 assert.equal(interpretSMTP(real,undefined,{host:'mail.attacker.test'}).status,'unknown');
});
test('temporary sender-stage rejections remain retryable, including policy-worded 4xx',()=>{
 assert.equal(classifyFailure(Error('Sender rejected or policy restriction: 452 server temporarily unavailable')).retryable,true);
 assert.equal(classifyFailure(Error('550 5.7.1 HELO command rejected')).retryable,false);
 assert.equal(classifyFailure(Error('TLS certificate error 421 temporary')).retryable,false);
});
test('Microsoft real-recipient DBEB rejection is reported distinctly from a generic policy block',()=>{
 const reply={code:550,text:'550 5.4.1 Recipient address rejected: Access denied. See https://aka.ms/EXOSmtpErrors'};
 assert.equal(interpretSMTP(reply,undefined,{host:'org.mail.protection.outlook.com'}).rule,'microsoft-recipient-rejected');
 assert.equal(interpretSMTP(reply,undefined,{host:'unrelated.test'}).status,'unknown');
});
import {interpretSMTP,classifyFailure,retryDue,assessOutcome,savedMailbox} from './dist/evidence.mjs';
import {probeHosts} from './smtp.mjs';
test('Microsoft rule requires provider host, exact DBEB signature, and positive real recipient',()=>{
 const yes={code:250,text:'250 Recipient OK'},random={code:550,text:'550 5.4.1 Recipient address rejected: Access denied. For more information see https://aka.ms/EXOSmtpErrors'};
 const match=interpretSMTP(yes,random,{host:'company-com.mail.protection.outlook.com'});
 assert.equal(match.status,'accepted');assert.equal(match.rule,'microsoft-dbeb-random-5.4.1');assert.equal(match.catchall_status,'no');
 for(const host of ['mail.example.com','mail.protection.outlook.com.attacker.example'])assert.equal(interpretSMTP(yes,random,{host}).status,'accepted-unconfirmed');
 assert.equal(interpretSMTP({code:450,text:'450 Try later'},random,{host:'a.mail.protection.outlook.com'}).status,'unknown');
 assert.equal(interpretSMTP(yes,{code:550,text:'550 5.4.1 Access denied'},{host:'a.mail.protection.outlook.com'}).status,'accepted-unconfirmed');
});
test('recipient acceptance and catch-all uncertainty remain separate',()=>{
 const r=interpretSMTP({code:250,text:'250 OK'},{code:550,text:'550 5.5.0 mailbox unavailable'});
 assert.equal(r.recipient_status,'accepted');assert.equal(r.catchall_status,'unknown');assert.equal(r.status,'accepted-unconfirmed');assert.equal(r.retryable,false);
 assert.equal(interpretSMTP({code:250,text:'250 OK'},{code:421,text:'421 temporary'}).retryable,true);
});
test('reviewing saved evidence preserves raw replies and does not invent a check for domain-only rows',()=>{
 const recipient_reply='250 OK',catchall_reply='550 5.4.1 Recipient address rejected: Access denied. See https://aka.ms/EXOSmtpErrors';
 const m=savedMailbox({recipient_reply,catchall_reply,smtp_host:'example.mail.protection.outlook.com',smtp_tls:'true'});
 assert.equal(m.status,'accepted');assert.equal(m.recipient_reply,recipient_reply);assert.equal(m.catchall_reply,catchall_reply);
 assert.equal(savedMailbox({mailbox_status:'not checked',evidence:'Mail servers found'}).check_failed,undefined);
});
test('connection failures try alternate MX; policy, TLS and successful checks do not',async()=>{
 let calls=[];const result=await probeHosts(['first.test','second.test'],'a@b.test','b.test',{probeFn:async host=>{calls.push(host);if(host==='first.test')throw Object.assign(Error('refused'),{code:'ECONNREFUSED'});return {status:'accepted'};}});
 assert.equal(result.status,'accepted');assert.equal(calls.length,2);assert.equal(result.attempt_history.length,2);
 for(const error of [Error('Hostname does not match certificate altnames'),Error('Sender rejected: 550 5.7.1 policy')]){calls=[];const r=await probeHosts(['first','second'],'a@b.test','b.test',{probeFn:async h=>{calls.push(h);throw error;}});assert.equal(calls.length,1);assert.equal(r.retryable,false);}
});
test('retry cooldown and limit exclude success, suppression and duplicates',()=>{
 const r={mailbox:{retryable:true},attempts:1,retry_at:'2026-11-03T10:15:00Z'};
 assert.equal(retryDue(r,Date.parse('2026-11-03T10:14:59Z')),false);assert.equal(retryDue(r,Date.parse('2026-11-03T10:15:00Z')),true);
 for(const extra of [{attempts:3},{suppressed:true},{duplicate:true},{mailbox:{retryable:false}}])assert.equal(retryDue({...r,...extra},Date.parse('2026-11-03T11:00:00Z')),false);
 assert.equal(classifyFailure(Error('550 5.7.1 IP blocked')).retryable,false);
});
test('outcome comparison excludes old events and surfaces conflicts',()=>{
 const r={email:'a@b.test',checked:'2026-11-03T10:00:00Z',mailbox:{status:'accepted'}};
 const event=(outcome,time)=>({email:'A@b.test',outcome,observed_at:time});
 assert.equal(assessOutcome(r,[event('hard_bounce','2026-11-02T10:00:00Z')]).outcome,'unobserved');
 assert.equal(assessOutcome(r,[event('hard_bounce','2026-11-03T11:00:00Z')]).assessment,'SMTP acceptance followed by hard bounce');
 assert.equal(assessOutcome(r,[event('hard_bounce','2026-11-03T11:00:00Z'),event('reply','2026-11-03T12:00:00Z')]).outcome,'conflicting');
});
test('DNS retries a refused resolver over HTTPS and preserves the successful provider',async()=>{
 const calls=[];const answer=await queryDNS('gmail.com','MX',{fetcher:async url=>{calls.push(url);if(calls.length===1)throw Error('ECONNREFUSED');return {ok:true,json:async()=>({Status:0,Answer:[{type:15,data:'10 mail.test.'}]})};}});
 assert.equal(calls.length,2);assert.equal(answer.resolver,'dns.google');assert.equal(answer.Status,0);
});
test('DNS retries SERVFAIL, but preserves NXDOMAIN rather than treating it as infrastructure failure',async()=>{
 let count=0;const result=await queryDNS('missing.invalid','MX',{fetcher:async()=>({ok:true,json:async()=>({Status:++count===1?2:3})})});assert.equal(count,2);assert.equal(result.Status,3);
});
test('both DNS providers failing yields an explicit check failure',async()=>{
 await assert.rejects(()=>queryDNS('gmail.com','MX',{fetcher:async()=>{throw Error('EDESTRUCTION');}}),/DNS check failed.*No mailbox conclusion/);
});
test('DNS cancellation prevents fallback and never becomes a nonexistent domain',async()=>{
 const control=new AbortController();control.abort();await assert.rejects(()=>queryDNS('gmail.com','MX',{signal:control.signal}),/cancelled/);
});
test('exported historical status takes priority over the new result on reimport',()=>{
 assert.deepEqual(records('email,result,imported_status\na@b.com,Check failed,valid'),[{email:'a@b.com',provider:'valid'}]);
});
test('CSV preserves quoted commas, newlines, BOM, escaped quotes and provider status',()=>{
 assert.deepEqual(parseCSV('\uFEFFemail,business\r\na@b.com,"A, B"\r\nx@y.com,"line1\nline2"'),[['email','business'],['a@b.com','A, B'],['x@y.com','line1\nline2']]);
 assert.deepEqual(records('email,verification_status\r\na@b.com,catch-all'),[{email:'a@b.com',provider:'catch-all'}]);
 assert.deepEqual(records('a@b.com\nb@c.com'),[{email:'a@b.com',provider:''},{email:'b@c.com',provider:''}]);
 assert.throws(()=>parseCSV('email\n"unterminated'));assert.throws(()=>records('business,phone\nCompany,123'));
});
test('syntax covers normal, malformed and unsupported international addresses',()=>{
 assert.equal(syntax('first.last+tag@company.co.uk').ok,true);assert.equal(syntax('info@COMPANY.COM').role,true);
 for(const e of ['x..y@company.com','.x@company.com','x.@company.com','x@-domain.com','x@domain','a@@b.com','a\r\n@b.com'])assert.equal(syntax(e).ok,false,e);
 assert.equal(syntax('“name”@company.com').unknown,true);assert.equal(syntax('用户@company.com').unknown,true);assert.equal(syntax('a'.repeat(65)+'@company.com').ok,false);
});
test('DNS correctly distinguishes null MX, fallback, NXDOMAIN and lookup errors',()=>{
 assert.equal(assessDNS({Status:0,Answer:[{type:15,data:'0 .'}]}).status,'invalid');
 assert.deepEqual(assessDNS({Status:0,Answer:[{type:15,data:'20 mx2.test.'},{type:15,data:'10 mx1.test.'}]}).hosts,['mx1.test','mx2.test']);
 assert.equal(assessDNS({Status:3}).status,'invalid');assert.equal(assessDNS({Status:2}).status,'unknown');
 assert.equal(assessDNS({Status:0},{Status:0,Answer:[{type:1,data:'1.2.3.4'}]},{Status:0}).fallback,true);
 assert.equal(assessDNS({Status:0},{Status:2},{Status:0}).status,'unknown');
 assert.equal(assessDNS({Status:0},{Status:0},{Status:0}).status,'invalid');
});
test('SMTP policy rejects and inconclusive responses never imply invalid mailbox',()=>{
 assert.equal(smtpOutcome({code:550,text:'550 5.7.1 Access denied'}).status,'unknown');
 assert.equal(smtpOutcome({code:450,text:'450 Try again'}).status,'unknown');
 assert.equal(smtpOutcome({code:550,text:'550 5.1.1 User unknown'}).status,'rejected');
 assert.equal(smtpOutcome({code:250,text:'250 OK'},{code:250,text:'250 OK'}).status,'catch-all');
 assert.equal(smtpOutcome({code:250,text:'250 OK'},{code:550,text:'550 5.1.1 User unknown'}).status,'accepted');
 assert.equal(smtpOutcome({code:250,text:'250 OK'},{code:550,text:'550 policy rejection'}).status,'accepted-unconfirmed');
});
test('CSV export neutralizes formula cells',()=>{assert.equal(csvCell('=HYPERLINK("x")'),'"\'=HYPERLINK(""x"")"');assert.equal(csvCell('a@b.com'),'"a@b.com"');});
test('private and reserved mail hosts are blocked',()=>{for(const ip of ['127.0.0.1','10.1.2.3','172.16.1.2','192.168.1.1','169.254.169.254','0.0.0.0','100.64.0.1','224.0.0.1','198.18.0.1','192.0.2.1','203.0.113.5','::1'])assert.equal(publicIP(ip),false,ip);assert.equal(publicIP('8.8.8.8'),true);});
function mockSocket({catchAll=false,policy=false,tls=false}={}){
 const socket=new EventEmitter();socket.localAddress='192.168.1.2';socket.commands=[];socket.destroy=()=>{};
 socket.write=line=>{for(const cmd of line.trim().split('\r\n')){socket.commands.push(cmd);let reply='250 OK\r\n';if(cmd.startsWith('EHLO'))reply=tls&&!socket.secure?'250-mail.test\r\n250 STARTTLS\r\n':'250-mail.test\r\n250 SIZE 1000000\r\n';if(cmd==='STARTTLS')reply='220 Ready for TLS\r\n';if(cmd.startsWith('RCPT TO:<mailcheck-')&&!catchAll)reply='550 5.1.1 User unknown\r\n';if(cmd.startsWith('RCPT')&&policy)reply='550 5.7.1 Policy block\r\n';if(cmd==='QUIT')reply='221 Bye\r\n';queueMicrotask(()=>socket.emit('data',Buffer.from(reply)));}return true;};
 return socket;
}
const resolve=async()=>[{address:'8.8.8.8',family:4}];
test('probe completes recipient and catch-all checks without transmitting DATA',async()=>{
 for(const catchAll of [false,true]){const socket=mockSocket({catchAll});const result=await probe('mail.test','user@company.test','company.test',{resolve,connect:()=>{queueMicrotask(()=>socket.emit('data',Buffer.from('220 mail.test ready\r\n')));return socket;}});assert.equal(result.status,catchAll?'catch-all':'accepted');assert.equal(socket.commands.filter(x=>x.startsWith('RCPT')).length,2);assert.equal(socket.commands.some(x=>x==='DATA'),false);}
});
test('probe preserves uncertainty on policy rejection and skips random probe',async()=>{const socket=mockSocket({policy:true});const result=await probe('mail.test','user@company.test','company.test',{resolve,connect:()=>{queueMicrotask(()=>socket.emit('data',Buffer.from('220 mail.test ready\r\n')));return socket;}});assert.equal(result.status,'unknown');assert.equal(socket.commands.filter(x=>x.startsWith('RCPT')).length,1);});
test('probe upgrades STARTTLS before issuing recipient commands',async()=>{const socket=mockSocket({tls:true});const result=await probe('mail.test','user@company.test','company.test',{resolve,connect:()=>{queueMicrotask(()=>socket.emit('data',Buffer.from('220 mail.test ready\r\n')));return socket;},upgrade:()=>{socket.secure=true;queueMicrotask(()=>socket.emit('secureConnect'));return socket;}});assert.equal(result.encrypted,true);assert.ok(socket.commands.indexOf('STARTTLS')<socket.commands.findIndex(x=>x.startsWith('RCPT')));assert.equal(socket.commands.filter(x=>x.startsWith('EHLO')).length,2);});
test('probe timeout closes socket and late DNS resolution cannot start a connection',async()=>{let connections=0;await assert.rejects(()=>probe('slow.test','a@b.test','b.test',{timeoutMs:5,resolve:()=>new Promise(r=>setTimeout(()=>r([{address:'8.8.8.8'}]),20)),connect:()=>{connections++;return mockSocket();}}),/timed out/);await new Promise(r=>setTimeout(r,25));assert.equal(connections,0);});
test('a catch-all timeout preserves the positive real-recipient evidence',async()=>{
 const socket=mockSocket();const write=socket.write;socket.write=line=>line==='RSET\r\n'?true:write(line);
 const result=await probe('mail.test','user@company.test','company.test',{timeoutMs:15,resolve,connect:()=>{queueMicrotask(()=>socket.emit('data',Buffer.from('220 ready\r\n')));return socket;}});
 assert.equal(result.status,'accepted-unconfirmed');assert.equal(result.recipient_reply,'250 OK');assert.equal(result.catchall_status,'unknown');assert.equal(result.retryable,true);
});
