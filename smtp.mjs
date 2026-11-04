import net from 'node:net';
import tls from 'node:tls';
import {cachedMailIPv4 as resolveMailIPv4} from './dns-cache.mjs';
import {randomBytes} from 'node:crypto';
import {smtpOutcome} from './dist/core.mjs';
import {classifyFailure} from './dist/evidence.mjs';
export function publicIP(ip){
 if(net.isIP(ip)!==4)return false;const p=ip.split('.').map(Number);
 return !(p[0]===0||p[0]===10||p[0]===127||p[0]>=224||(p[0]===169&&p[1]===254)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&(p[1]===168||p[1]===0||p[1]===2))||(p[0]===100&&p[1]>=64&&p[1]<=127)||(p[0]===198&&(p[1]===18||p[1]===19||p[1]===51))||(p[0]===203&&p[1]===0&&p[2]===113));
}
function reader(socket){
 let buffer='',parts=[],responses=[],waiting,closed;
 const deliver=r=>{if(waiting){const w=waiting;waiting=null;w.resolve(r);}else responses.push(r);};
 const fail=e=>{closed=e;if(waiting){const w=waiting;waiting=null;w.reject(e);}};
 const ondata=chunk=>{buffer+=chunk.toString();if(buffer.length+parts.join('').length>65536)return fail(Error('SMTP response too large'));let pos;while((pos=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,pos).trimEnd();buffer=buffer.slice(pos+1);const match=line.match(/^(\d{3})([ -])(.*)$/);if(!match)continue;parts.push(line);if(match[2]===' '){deliver({code:Number(match[1]),text:parts.join('\n')});parts=[];}}};
 const onerror=e=>fail(e),onclose=()=>fail(Error('SMTP connection closed before verification completed'));
 socket.on('data',ondata);socket.on('error',onerror);socket.on('close',onclose);
 return {read(){if(responses.length)return Promise.resolve(responses.shift());if(closed)return Promise.reject(closed);return new Promise((resolve,reject)=>{waiting={resolve,reject};});},dispose(){socket.off('data',ondata);socket.off('error',onerror);socket.off('close',onclose);}};
}
export async function probe(host,email,domain,{connect=net.createConnection,resolve=resolveMailIPv4,upgrade=tls.connect,timeoutMs=25000}={}){
 let socket,channel,timer,cancelled=false,evidence;
 const task=async()=>{
  const ips=await resolve(host,{all:true,family:4});if(cancelled)throw Error('Probe cancelled');if(!ips.length||ips.some(x=>!publicIP(x.address)))throw Error('Mail host has no permitted public IPv4 address');
  socket=connect({host:ips[0].address,port:25});channel=reader(socket);
  const command=async line=>{socket.write(line+'\r\n');return channel.read();};
  const requireCode=(r,code,stage)=>{if(r.code!==code)throw Error(stage+': '+r.text);return r;};
  requireCode(await channel.read(),220,'SMTP greeting rejected');
  const configured=process.env.MAILCHECK_HELO;const helo=configured&&/^[a-zA-Z0-9.-]+$/.test(configured)?configured:`[${socket.localAddress||'127.0.0.1'}]`;
  let hello=await command('EHLO '+helo);
  if([500,502,504].includes(hello.code))hello=await command('HELO '+helo);
  requireCode(hello,250,'Server rejected greeting');
  let encrypted=false;
  if(/^250[ -]STARTTLS\b/im.test(hello.text)){
   requireCode(await command('STARTTLS'),220,'TLS upgrade rejected');channel.dispose();
   const plain=socket;socket=upgrade({socket:plain,servername:host,rejectUnauthorized:true});channel=reader(socket);
   await new Promise((resolve,reject)=>{const success=()=>{socket.off('error',failure);resolve();};const failure=e=>{socket.off('secureConnect',success);reject(e);};socket.once('secureConnect',success);socket.once('error',failure);});
   requireCode(await command('EHLO '+helo),250,'TLS greeting rejected');encrypted=true;
  }
  requireCode(await command('MAIL FROM:<>'),250,'Sender rejected or policy restriction');
  const real=await command(`RCPT TO:<${email}>`);
  evidence={...smtpOutcome(real,undefined,{host}),host,encrypted,recipient_reply:real.text,recipient_code:real.code};
  if(real.code!==250){socket.write('RSET\r\nQUIT\r\n');return {...smtpOutcome(real,undefined,{host}),encrypted,host,recipient_reply:real.text,recipient_code:real.code};}
  requireCode(await command('RSET'),250,'Server would not reset transaction');
  requireCode(await command('MAIL FROM:<>'),250,'Sender rejected for catch-all check');
  const random=await command(`RCPT TO:<mailcheck-${randomBytes(15).toString('hex')}@${domain}>`);
  socket.write('RSET\r\nQUIT\r\n');return {...smtpOutcome(real,random,{host}),encrypted,host,recipient_reply:real.text,recipient_code:real.code,catchall_reply:random.text,catchall_code:random.code};
 };
 try{return await Promise.race([task(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('SMTP timed out; port 25 may be blocked')),timeoutMs);})]);}catch(error){if(evidence?.recipient_status==='accepted')return {...evidence,reason:evidence.reason+'; catch-all check interrupted: '+error.message,retryable:classifyFailure(error).retryable};throw error;}finally{cancelled=true;clearTimeout(timer);channel?.dispose();socket?.destroy();}
}

export async function probeHosts(hosts,email,domain,{probeFn=probe}={}){
 const attempts=[];
 for(const host of [...new Set(hosts)].slice(0,2)){
  try{const result=await probeFn(host,email,domain);attempts.push({host,status:result.status,reason:result.reason});return {...result,attempt_history:attempts};}
  catch(error){const failure=classifyFailure(error);attempts.push({host,...failure});if(failure.failure_kind!=='connection')return {...failure,host,attempt_history:attempts};}
 }
 const last=attempts.at(-1)||classifyFailure(Error('No mail host found'));
 return {...last,attempt_history:attempts};
}
