import {queryDNS} from './dist/dns-query.mjs';
// Backend-only cache. DNS answers expire by their advertised TTL (at most five minutes).
// No recipient addresses or failed lookups are stored.
export function createCachedResolver(loader=queryDNS,now=Date.now){
 const cache=new Map();
 return async(domain,type)=>{
  const key=domain.toLowerCase()+':'+type;const entry=cache.get(key);if(entry&&entry.until>now())return entry.value;
  const value=await loader(domain,type);const ttl=value.Status===3?30:Math.min(300,...(value.Answer||[]).map(x=>Math.max(0,Number(x.TTL)||0)));
  if([0,3].includes(value.Status)&&ttl>0){if(cache.size>=256)cache.delete(cache.keys().next().value);cache.set(key,{value,until:now()+ttl*1000});}return value;
 };
}
export const cachedDNS=createCachedResolver();
export async function cachedMailIPv4(host){const data=await cachedDNS(host,'A');if(data.Status===3)throw Error('Mail host does not exist');const ips=(data.Answer||[]).filter(r=>r.type===1).map(r=>({address:r.data,family:4}));if(!ips.length)throw Error('Mail host has no IPv4 record; mailbox not verified');return ips;}
