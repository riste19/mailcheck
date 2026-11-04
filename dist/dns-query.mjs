// Shared by the browser and local backend; never uses Node's shared UDP resolver.
export async function queryDNS(domain,type,{signal,fetcher=fetch,timeoutMs=6500}={}){
 const providers=['https://cloudflare-dns.com/dns-query','https://dns.google/resolve'];const failures=[];
 for(const provider of providers){
  if(signal?.aborted)throw Error('Check cancelled');
  const controller=new AbortController();const cancel=()=>controller.abort();signal?.addEventListener('abort',cancel,{once:true});const timer=setTimeout(cancel,timeoutMs);
  try{
   const response=await fetcher(`${provider}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}&edns_client_subnet=0.0.0.0%2F0`,{headers:{accept:'application/dns-json'},signal:controller.signal});
   if(!response.ok)throw Error('HTTP '+response.status);
   const data=await response.json();
   if(![0,3].includes(data.Status)||data.TC)throw Error('DNS service returned '+(data.TC?'a truncated response':'status '+data.Status));
   if(data.Answer&&!Array.isArray(data.Answer))throw Error('Malformed DNS response');
   return {...data,resolver:new URL(provider).hostname};
  }catch(e){if(signal?.aborted)throw Error('Check cancelled');failures.push(new URL(provider).hostname+': '+(controller.signal.aborted?'timeout':e.message));}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);}
 }
 throw Error('DNS check failed ('+failures.join('; ')+'). No mailbox conclusion can be drawn.');
}
export async function resolveMailIPv4(host){
 const data=await queryDNS(host,'A');if(data.Status===3)throw Error('Mail host does not exist');
 const ips=(data.Answer||[]).filter(r=>r.type===1).map(r=>({address:r.data,family:4}));
 if(!ips.length)throw Error('Mail host has no IPv4 record; mailbox not verified');return ips;
}
