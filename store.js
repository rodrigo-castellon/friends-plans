// Encrypted inbox. Submissions are encrypted in the browser with Rodrigo's PUBLIC key;
// only the private key (kept solely in his admin link) can read them. The relay/archive only ever sees ciphertext.
const FP={TOPIC:"fp-9c758d850612653521bce44d",PUB:"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoXUHMk9pfNyg3ofxWJBqxx+ZE6a5woeADpuuclFi3a7RRxtvO3m1iOsyVHFHsjFLa9InqAwMvUD+DXQmoO91MsnN7iPj+pBZCgVA5f5X+bdpjp1JjUyOzVMcyybiODp4ANmHqETN68PkVa2BS/zCVraV9OFdSgOOVeu/8mdx4uH+JxFhZ5XVdbJryXNtRMxzpW058w7q3nMTFaP/t8qAgRp87HNPnN/ntO+Tc4RhNTbYHMqiH1SWO48KofeYMBOtWQjbmZ7Ud6a/35p9hSUX2unNat7RKzpY8aR5RDldEU0t5ygkj5AxUUxa9TMsETlSA7dW4EJbmhwxNqSRQMBnTQIDAQAB",RELAY:"https://ntfy.sh",ARCHIVE:"data/msgs.jsonl"};
const te=new TextEncoder(),td=new TextDecoder();
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));const unb64=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async s=>crypto.subtle.digest('SHA-256',te.encode(s));
FP.newToken=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
FP.sid=async tok=>hex(await sha('sid:'+tok)).slice(0,32);
FP.friendKey=async tok=>crypto.subtle.importKey('raw',await sha('fk:'+tok),'AES-GCM',false,['encrypt','decrypt']);
FP.seal=async(tok,payload)=>{
 const pub=await crypto.subtle.importKey('spki',unb64(FP.PUB),{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
 const raw=crypto.getRandomValues(new Uint8Array(32)),k=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt']);
 const iv=crypto.getRandomValues(new Uint8Array(12)),fiv=crypto.getRandomValues(new Uint8Array(12));
 const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,te.encode(JSON.stringify({...payload,tok})));
 const ek=await crypto.subtle.encrypt({name:'RSA-OAEP'},pub,raw);
 const fk=await crypto.subtle.encrypt({name:'AES-GCM',iv:fiv},await FP.friendKey(tok),raw);
 return JSON.stringify({v:1,sid:await FP.sid(tok),ts:Date.now(),iv:b64(iv),ct:b64(ct),ek:b64(ek),fiv:b64(fiv),fk:b64(fk)});};
FP.post=async msg=>{if(msg.length>3900)throw new Error('too_long');
 const r=await fetch(FP.RELAY+'/'+FP.TOPIC,{method:'POST',body:msg});if(!r.ok)throw new Error('relay '+r.status);return r.json();};
// Returns [{id,time,m}] from the durable archive (GitHub, updated every ~10 min) + live relay (last 12h)
FP.fetchAll=async()=>{const out=new Map();
 const add=(id,time,s)=>{try{const m=JSON.parse(s);if(m&&m.v===1&&m.sid)out.set(id,{id,time,m})}catch(e){}};
 try{const t=await (await fetch(FP.ARCHIVE+'?_='+Date.now(),{cache:'no-store'})).text();t.split('\n').forEach(l=>{try{const o=JSON.parse(l);add(o.id,o.time,o.message)}catch(e){}})}catch(e){}
 try{const t=await (await fetch(FP.RELAY+'/'+FP.TOPIC+'/json?poll=1&since=all',{cache:'no-store'})).text();t.split('\n').forEach(l=>{try{const o=JSON.parse(l);if(o.event==='message')add(o.id,o.time,o.message)}catch(e){}})}catch(e){}
 return [...out.values()].sort((a,b)=>a.time-b.time||a.m.ts-b.m.ts);};
FP.openAES=async(rawKey,iv,ct)=>{const k=await crypto.subtle.importKey('raw',rawKey,'AES-GCM',false,['decrypt']);return JSON.parse(td.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(iv)},k,unb64(ct))));};
// Friend: latest own record (null if none / deleted)
FP.mine=async tok=>{const sid=await FP.sid(tok),fk=await FP.friendKey(tok);let last=null;
 for(const x of await FP.fetchAll()){if(x.m.sid!==sid)continue;try{const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(x.m.fiv)},fk,unb64(x.m.fk));last=await FP.openAES(raw,x.m.iv,x.m.ct)}catch(e){}}
 return last;};
// Admin: decrypt all, verify token ownership, latest per submitter wins
FP.adminLoad=async privB64=>{const priv=await crypto.subtle.importKey('pkcs8',unb64(privB64),{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
 const latest={};for(const x of await FP.fetchAll()){try{const raw=await crypto.subtle.decrypt({name:'RSA-OAEP'},priv,unb64(x.m.ek));const p=await FP.openAES(raw,x.m.iv,x.m.ct);
  if(await FP.sid(p.tok)!==x.m.sid)continue;latest[x.m.sid]={...p,updated:new Date(x.time*1000).toISOString()}}catch(e){}}
 const rows=[];let id=0;Object.values(latest).forEach(p=>{if(p.deleted)return;(p.stops||[]).forEach(s=>rows.push({id:id++,name:p.name,contact:p.contact||'',city:s.city,start:s.start,end:s.end,note:s.note||'',updated:p.updated}))});return rows;};
