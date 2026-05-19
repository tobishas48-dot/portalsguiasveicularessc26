const crypto = require("crypto");
const HMAC_SECRET = "sc-guias-2026-1167a8c9359ce493353764016606e2b20678376b1f68be2d8a0c6c319dc5af05-fixed";
const SLUG_TTL_SECONDS = 600;

function b64url(b){return Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function hmacSign(m){return b64url(crypto.createHmac("sha256",HMAC_SECRET).update(m).digest());}
function safeEqual(a,b){if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0;}
function verifySlug(slug){
  if(!slug)return false;const p=slug.split(".");if(p.length!==3)return false;
  const [tsStr,nonce,sig]=p;const ts=parseInt(tsStr,10);
  if(!ts||!nonce||!sig)return false;
  if(!safeEqual(sig,hmacSign(`${ts}.${nonce}`)))return false;
  const now=Math.floor(Date.now()/1000);
  if(now-ts>SLUG_TTL_SECONDS)return false;
  return true;
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  let body; try { body = JSON.parse(event.body||"{}"); } catch { return { statusCode:400, body:"{}" }; }
  const slug = (body.slug||"").toString();
  if (!verifySlug(slug)) return { statusCode:403, headers:{"Content-Type":"application/json"}, body: JSON.stringify({error:"invalid"}) };
  return { statusCode:200, headers:{"Content-Type":"application/json","Cache-Control":"no-store"}, body: JSON.stringify({ challenge: hmacSign(`challenge.${slug}`) }) };
};
