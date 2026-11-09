/**
 * Login page delivered on a verified but unauthenticated SSO request. The
 * original request query stays in the address bar: after sign-in succeeds the
 * page reloads the same URL, so the binding signature, validation and one-time
 * claim all run again on the authenticated round. There is no redirect
 * parameter and therefore no handoff redirect to forge.
 */

const EMAIL_ENDPOINT = "/api/auth/sign-in/email";
const USERNAME_ENDPOINT = "/api/auth/sign-in/username";

export function buildSsoLoginPage(options: {
  title: string;
  hint: string;
}): string {
  return [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/>',
    `<title>${htmlEscape(options.title)}</title>`,
    "<style>",
    "body{font-family:system-ui,sans-serif;background:#f6f6f8;display:flex;min-height:100vh;align-items:center;justify-content:center}",
    "main{background:#fff;border:1px solid #e4e4e9;border-radius:10px;padding:32px;width:min(320px,90vw)}",
    "h1{font-size:17px;margin:0 0 4px}",
    "p{font-size:13px;color:#5c5c66;margin:0 0 18px}",
    "label{display:block;font-size:12px;margin:10px 0 4px;color:#3c3c44}",
    "input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cfcfd8;border-radius:6px;font-size:14px}",
    "button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:6px;background:#2f5fe0;color:#fff;font-size:14px;cursor:pointer}",
    "button[disabled]{opacity:.6}",
    "#error{color:#b3261e;font-size:13px;margin-top:12px;min-height:16px}",
    "</style></head><body>",
    "<main>",
    `<h1>${htmlEscape(options.title)}</h1>`,
    `<p>${htmlEscape(options.hint)}</p>`,
    "<form id=\"f\" method=\"post\" autocomplete=\"off\"",
    ">",
    '<label for="identifier">Email or username</label>',
    '<input id="identifier" name="identifier" type="text" required autocapitalize="off"/>',
    '<label for="password">Password</label>',
    '<input id="password" name="password" type="password" required/>',
    '<button id="b" type="submit">Continue</button>',
    '<button id="passkey" type="button" style="margin-top:10px;background:#5f6368">Sign in with a passkey</button>',
    '<div id="error" role="alert"></div>',
    "</form>",
    "</main>",
    `<script>var EMAIL='${EMAIL_ENDPOINT}';var USER='${USERNAME_ENDPOINT}';
var f=document.getElementById('f'),b=document.getElementById('b'),e=document.getElementById('error');
f.addEventListener('submit',function(ev){ev.preventDefault();b.disabled=true;e.textContent='';
var id=document.getElementById('identifier').value.trim();var pw=document.getElementById('password').value;
var endpoint=/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(id)?EMAIL:USER;
var payload=endpoint===EMAIL?{email:id,password:pw}:{username:id,password:pw};
fetch(endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
.then(function(r){return r.json().then(function(j){return {status:r.status,json:j};},function(){return {status:r.status,json:{}};});})
.then(function(res){
if(res.status===200){location.reload();return;}
b.disabled=false;
e.textContent=res.status===429?'Too many attempts. Try again shortly.':(res.status===401||res.status===400?'Sign-in failed. Check your credentials.':'Sign-in is unavailable. Try again later.');})
.catch(function(){b.disabled=false;e.textContent='Sign-in is unavailable. Try again later.';});});

var pk=document.getElementById('passkey');
function b64urlToBuffer(s){var b=s.replace(/-/g,'+').replace(/_/g,'/');var d=atob(b+'='.slice(0,(4-b.length%4)%4));var v=new Uint8Array(d.length);for(var i=0;i<d.length;i++)v[i]=d.charCodeAt(i);return v;}
function bufferToB64url(v){var s='';var u=new Uint8Array(v);for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/=+$/g,'').replace(/\\+/g,'-').replace(/\\//g,'_');}
pk.addEventListener('click',function(){
pk.disabled=true;e.textContent='';
fetch('/api/auth/passkey/generate-authenticate-options',{method:'GET',credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(o){
if(!o.challenge){throw new Error('no-options');}
var publicKey={challenge:b64urlToBuffer(o.challenge),
rpId:o.rpId||location.hostname,
timeout:o.timeout||60000,
userVerification:o.userVerification||'preferred',
allowCredentials:(o.allowCredentials||[]).map(function(c){return {id:b64urlToBuffer(c.id),type:'public-key',transports:c.transports};})};
return navigator.credentials.get({publicKey:publicKey});
})
.then(function(assertion){
if(!assertion){return null;}
var body={id:assertion.id,rawId:assertion.id,type:assertion.type,clientExtensionResults:{},
response:{clientDataJSON:bufferToB64url(assertion.response.clientDataJSON),
authenticatorData:bufferToB64url(assertion.response.authenticatorData),
signature:bufferToB64url(assertion.response.signature),
userHandle:assertion.response.userHandle?bufferToB64url(assertion.response.userHandle):null}};
return fetch('/api/auth/passkey/verify-authentication',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({response:body})});
})
.then(function(r){
if(!r){pk.disabled=false;return;}
if(r.ok){location.reload();return;}
pk.disabled=false;e.textContent='Passkey sign-in failed. Use your password.';
})
.catch(function(err){
pk.disabled=false;
e.textContent=err&&err.message==='no-options'?'A passkey cannot be used right now. Sign in with your password.':'Passkey sign-in was cancelled or unavailable. Use your password.';
});
});
</script></body></html>`,
  ].join("");
}

function htmlEscape(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&apos;";
    }
  });
}
