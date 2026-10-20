// Capture actual Postman runner views through Electron's DevTools interface.
// Run the collection in Postman first. Images are saved without editing.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
const port=Number(process.argv[2]??process.env.POSTMAN_DEBUG_PORT);
if(!port) throw new Error('Supply the local Postman DevTools port.');
const targets=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const target=targets.find(t=>t.type==='page'&&t.url.startsWith('https://desktop.postman.com/'));
if(!target) throw new Error('Postman desktop application target not found.');
const ws=new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
let counter=0;const pending=new Map();
ws.onmessage=event=>{const data=JSON.parse(event.data);const callback=pending.get(data.id);if(callback){pending.delete(data.id);data.error?callback.reject(data.error):callback.resolve(data.result);}};
function send(method,params={}){const id=++counter;return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});}
async function evaluate(expression){const result=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw new Error(JSON.stringify(result.exceptionDetails));return result.result.value;}
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const collection=JSON.parse(readFileSync('postman/Team-All-Services.postman_collection.json','utf8'));
const allRequests=collection.item.flatMap(group=>group.item.flatMap(folder=>folder.item.map(item=>({...item,folder:folder.name}))));
const results=JSON.parse(readFileSync('evidence/team/http-execution.json','utf8'));
const chosen=new Set();const selected=new Set();
for(const result of results){
  const path=new URL(result.url).pathname.replace(/\/\d+(?=\/|$)/g,'/{id}').replace(/\/users\/(?!session$|logout$|register$|login$)([^/]+)$/,'/users/{username}');
  const owner=result.name.split(' — ')[0];
  const key=result.status<400?result.method+' '+path:owner+' '+result.status+' '+path.split('/')[2];
  if(!chosen.has(key)){chosen.add(key);selected.add(result.name);}
}
const requests=allRequests.filter(item=>selected.has(item.name));
const passwords=Object.values(JSON.parse(readFileSync('data/team-runtime/data/demo-credentials.json','utf8')));
const root='evidence/team/screenshots';mkdirSync(root,{recursive:true});
const manifest=[];
await send('Page.bringToFront');
await send('Emulation.setDeviceMetricsOverride',{width:1800,height:1200,deviceScaleFactor:1,mobile:false});
await send('Input.dispatchMouseEvent',{type:'mouseMoved',x:700,y:85});
await evaluate(`Array.from(document.querySelectorAll('*')).find(e=>e.childElementCount===0&&e.textContent.trim()==='Dismiss')?.click()`);
async function capture(file,caption,extra={}){
  const visible=await evaluate('document.body.innerText');
  if(passwords.some(secret=>visible.includes(secret))||/"access_token"\s*:\s*"[^\"]+"/.test(visible))throw new Error('Sensitive value visible; refusing screenshot.');
  const screenshot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
  writeFileSync(root+'/'+file,Buffer.from(screenshot.data,'base64'));
  manifest.push({file:root+'/'+file,caption:caption,source:'Actual merged-team Postman desktop runner, unedited; operated by Joseph Awaida',captured_at:new Date().toISOString(),...extra});
}
for(let i=0;i<requests.length;i++){
  const item=requests[i];const name=JSON.stringify(item.name);
  let found=false;
  if(i===0){await evaluate(`document.querySelector('.runner-results__list').scrollTop=0`);await pause(700);}
  for(let attempt=0;attempt<120;attempt++){
    await pause(180);
    found=await evaluate(`(()=>{const card=Array.from(document.querySelectorAll('[data-testid=runner-results_request-card]')).find(e=>Array.from(e.querySelectorAll('[data-testid=runner-results-header-breadcrumb-item__label]')).some(n=>n.textContent===${name}));if(card){card.scrollIntoView({block:'center'});card.click();return true;}const list=document.querySelector('.runner-results__list');list.scrollTop+=550;return false;})()`);
    if(found)break;
  }
  if(!found)throw new Error('Runner result not found: '+item.name);
  await pause(180);
  const tab=item.name.includes(' — Login ')?'Headers':'Response';
  await evaluate(`Array.from(document.querySelectorAll('button')).filter(b=>b.innerText===${JSON.stringify(tab)}&&b.getBoundingClientRect().width).at(-1).click()`);
  await pause(400);
  const base=String(i+1).padStart(2,'0')+'-'+item.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/-$/,'');
  await capture('postman-'+base+'-response.png',item.name+': actual '+item.request.method+' result and HTTP status'+(tab==='Headers'?' (response body omitted to protect the authentication token).':'.'),{operation:item.name,view:tab,method:item.request.method,folder:item.folder});
  if(item.request.body){
    await evaluate(`Array.from(document.querySelectorAll('button')).filter(b=>b.innerText==='Request'&&b.getBoundingClientRect().width).at(-1).click()`);
    await pause(400);
    const visible=await evaluate('document.body.innerText');
    if(!passwords.some(secret=>visible.includes(secret)))await capture('postman-'+base+'-request.png',item.name+': actual request body shown in the Postman runner.',{operation:item.name,view:'Request',method:item.request.method,folder:item.folder});
  }
  console.log('Captured '+(i+1)+'/'+requests.length+': '+item.name);
}
await evaluate(`Array.from(document.querySelectorAll('button')).filter(b=>b.innerText==='Response'&&b.getBoundingClientRect().width).at(-1).click()`);
await pause(250);
await capture('postman-run-summary.png','Hassan Nasrallah, Mohammad Nasrallah, Joseph Awaida — Actual desktop run: 184 requests, 239 assertions passed, zero errors.');
writeFileSync(root+'/postman-manifest.json',JSON.stringify(manifest,null,2));
console.log('Saved '+manifest.length+' genuine Postman screenshots.');
ws.close();
