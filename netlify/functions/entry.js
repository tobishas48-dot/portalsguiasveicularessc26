const crypto = require("crypto");
const ENTRY_TOKEN = "online";
const FALLBACK_URL = "https://www.google.com";
const HMAC_SECRET = "sc-guias-2026-1167a8c9359ce493353764016606e2b20678376b1f68be2d8a0c6c319dc5af05-fixed";

function b64url(buf){return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function randomNonce(len=10){const a="abcdefghijkmnpqrstuvwxyz23456789";const b=crypto.randomBytes(len);let o="";for(let i=0;i<len;i++)o+=a[b[i]%a.length];return o;}
function hmacSign(m){return b64url(crypto.createHmac("sha256",HMAC_SECRET).update(m).digest());}
function makeSlug(){const ts=Math.floor(Date.now()/1000);const n=randomNonce(10);const p=`${ts}.${n}`;return `${p}.${hmacSign(p)}`;}

exports.handler = async (event) => {
  const host = event.headers.host || "localhost";
  const proto = event.headers["x-forwarded-proto"] || "https";
  const go = (event.queryStringParameters && event.queryStringParameters.go) || "";
  if (go !== ENTRY_TOKEN) {
    return { statusCode: 302, headers: { Location: FALLBACK_URL, "Cache-Control": "no-store" }, body: "" };
  }
  const slug = makeSlug();
  return {
    statusCode: 302,
    headers: { Location: `${proto}://${host}/s/${slug}`, "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0" },
    body: "",
  };
};
