#!/usr/bin/env node
const base=(process.env.API_BASE||"").replace(/\/$/,"");
if(!base){console.error("Set API_BASE, e.g. https://prepos-api.onrender.com/api/v1");process.exit(1)}
const r=await fetch(base+"/health");
console.log("HTTP",r.status,await r.text());
process.exit(r.ok?0:1);
