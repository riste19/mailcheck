import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {cachedDNS as queryDNS} from './dns-cache.mjs';
import {fileURLToPath} from 'node:url';
import {syntax} from './dist/core.mjs';
import {probeHosts} from './smtp.mjs';
import {classifyFailure} from './dist/evidence.mjs';
const port=Number(process.env.PORT||4317), origin=`http://127.0.0.1:${port}`;
let active=0;
const server=http.createServer(async(req,res)=>{
 const reply=(code,data)=>{res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
 if(req.headers.host!==`127.0.0.1:${port}`)return reply(403,{error:'Use the loopback address printed by the server'});
 const url=new URL(req.url,origin);
 if(url.pathname==='/api/health')return reply(200,{smtp:true});
 if(url.pathname==='/api/probe'){
  if(req.method!=='POST'||req.headers.origin!==origin||req.headers['content-type']!=='application/json')return reply(403,{error:'Local app requests only'});
  if(active>=2)return reply(429,{error:'Verifier busy; retry shortly'});
  let body='';try{for await(const chunk of req){body+=chunk;if(body.length>2048)return reply(413,{error:'Request too large'});}const {email}=JSON.parse(body);const s=syntax(email);if(!s.ok)return reply(400,{error:s.reason});active++;
   try{const answer=await queryDNS(s.domain,'MX');
    if(answer.Status===3)return reply(200,{status:'rejected',reason:'Domain does not exist; no SMTP probe attempted',stage:'domain'});
    const mx=(answer.Answer||[]).filter(r=>r.type===15).map(r=>{const [priority,exchange]=r.data.trim().split(/\s+/);return {priority:Number(priority),exchange:exchange==='.'?'.':exchange.replace(/\.$/,'')};});
    if(mx.some(x=>!x.exchange||x.exchange==='.'))return reply(200,{status:'rejected',reason:'Domain explicitly does not accept mail'});
    const hosts=mx.sort((a,b)=>a.priority-b.priority).map(x=>x.exchange);
    reply(200,await probeHosts(hosts.length?hosts:[s.domain],email,s.domain));
   }catch(e){reply(200,classifyFailure(e));}finally{active--;}
  }catch{reply(400,{error:'Invalid request'});}return;
 }
 const allowed={'/':'index.html','/app.mjs':'app.mjs','/core.mjs':'core.mjs','/dns-query.mjs':'dns-query.mjs','/evidence.mjs':'evidence.mjs','/style.css':'style.css','/disposable-domains.txt':'disposable-domains.txt','/disposable-list-LICENSE.txt':'disposable-list-LICENSE.txt','/mailcheck-local.zip':'mailcheck-local.zip'};
 if(!allowed[url.pathname])return reply(404,{error:'Not found'});
 try{const data=await readFile(new URL('./dist/'+allowed[url.pathname],import.meta.url));res.writeHead(200,{'Content-Type':url.pathname.endsWith('.mjs')?'text/javascript':url.pathname.endsWith('.css')?'text/css':url.pathname.endsWith('.txt')?'text/plain':url.pathname.endsWith('.zip')?'application/zip':'text/html','X-Content-Type-Options':'nosniff'});res.end(data);}catch{reply(500,{error:'App file unavailable'});}
});
if(process.argv[1]===fileURLToPath(import.meta.url)){
 server.on('error',error=>{console.error(error.code==='EADDRINUSE'?`Mailcheck port ${port} is already in use. Close the old verifier's terminal window, then start the updated version.`:error.message);process.exitCode=1;});
 server.listen(port,'127.0.0.1',()=>console.log(`Mailcheck ready: ${origin}`));
}
