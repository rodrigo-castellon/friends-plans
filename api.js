async function api(body){
  if(!window.API_URL) throw new Error('Not configured yet (config.js API_URL is empty).');
  const r=await fetch(window.API_URL,{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body:JSON.stringify(body),redirect:'follow'});
  return r.json();
}
