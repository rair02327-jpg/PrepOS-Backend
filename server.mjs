import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import argon2 from "argon2";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import pg from "pg";
const {Pool}=pg,app=express(),PORT=Number(process.env.PORT||8080),isProd=process.env.NODE_ENV==="production";
for(const k of ["DATABASE_URL","JWT_ACCESS_SECRET","JWT_REFRESH_SECRET"])if(!process.env[k])throw new Error(`Missing ${k}`);
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==="disable"?false:{rejectUnauthorized:false},max:Number(process.env.DB_POOL_MAX||10)});
app.set("trust proxy",1);app.use(helmet({crossOriginResourcePolicy:false}));app.use(express.json({limit:"25mb"}));app.use(cookieParser());
const origins=(process.env.CORS_ORIGINS||"").split(",").map(x=>x.trim()).filter(Boolean);
// WebIntoApp packages local HTML inside an Android WebView. Such requests may
// carry the Origin header as "null". Allow that explicit origin plus any
// production web origins listed in CORS_ORIGINS. Credentials are required for
// the HttpOnly refresh cookie.
const corsOrigin=(o,cb)=>{
  if(!o || o === "null" || origins.includes(o)) return cb(null,true);
  return cb(new Error("CORS origin not allowed"));
};
app.use(cors({origin:corsOrigin,credentials:true,methods:["GET","POST","PUT","PATCH","DELETE","OPTIONS"],allowedHeaders:["Content-Type","Authorization"]}));
const authLimiter=rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false});
const apiLimiter=rateLimit({windowMs:60*1000,limit:300,standardHeaders:true,legacyHeaders:false});
const access=u=>jwt.sign({sub:u.id,role:u.role},process.env.JWT_ACCESS_SECRET,{expiresIn:"15m",issuer:"prepos-api",audience:"prepos-app"});
const refresh=(u,sid)=>jwt.sign({sub:u.id,sid},process.env.JWT_REFRESH_SECRET,{expiresIn:"30d",issuer:"prepos-api",audience:"prepos-app"});
const setCookie=(res,t)=>res.cookie("prepos_refresh",t,{httpOnly:true,secure:isProd,sameSite:"none",path:"/api/v1/auth",maxAge:30*86400000});
async function auth(req,res,next){try{const h=req.get("authorization")||"";if(!h.startsWith("Bearer "))throw 0;const p=jwt.verify(h.slice(7),process.env.JWT_ACCESS_SECRET,{issuer:"prepos-api",audience:"prepos-app"});const {rows}=await pool.query("select id,email,role,created_at from users where id=$1 and disabled=false",[p.sub]);if(!rows[0])throw 0;req.user=rows[0];next()}catch(_e){res.status(401).json({error:{message:"Authentication required"}})}}
const creds=z.object({email:z.string().email().max(320),password:z.string().min(8).max(128)});
app.get("/api/v1/health",async(_q,res)=>{try{await pool.query("select 1");res.json({ok:true,database:"up",time:new Date().toISOString()})}catch(_e){res.status(503).json({ok:false,database:"down"})}});
app.use("/api/v1/auth",authLimiter);
app.post("/api/v1/auth/register",async(req,res)=>{const p=creds.safeParse(req.body);if(!p.success)return res.status(400).json({error:{message:"Valid email and password are required"}});try{
 const email=p.data.email.toLowerCase().trim(),hash=await argon2.hash(p.data.password,{type:argon2.argon2id}),id=randomUUID(),c=await pool.connect();
 try{await c.query("begin");const {rows}=await c.query("insert into users(id,email,password_hash) values($1,$2,$3) returning id,email,role,created_at",[id,email,hash]);const u=rows[0],sid=randomUUID(),rt=refresh(u,sid);await c.query("insert into sessions(id,user_id,refresh_token_hash,expires_at) values($1,$2,$3,now()+interval '30 days')",[sid,id,await argon2.hash(rt)]);await c.query("commit");setCookie(res,rt);res.status(201).json({accessToken:access(u),user:u})}
 catch(e){await c.query("rollback");if(e.code==="23505")return res.status(409).json({error:{message:"Email already registered"}});throw e}finally{c.release()}
}catch(e){console.error(e);res.status(500).json({error:{message:"Registration failed"}})}});
app.post("/api/v1/auth/login",async(req,res)=>{const p=creds.safeParse(req.body);if(!p.success)return res.status(400).json({error:{message:"Valid email and password are required"}});const {rows}=await pool.query("select id,email,role,password_hash,created_at from users where email=$1 and disabled=false",[p.data.email.toLowerCase().trim()]);if(!rows[0]||!(await argon2.verify(rows[0].password_hash,p.data.password)))return res.status(401).json({error:{message:"Invalid email or password"}});const u={id:rows[0].id,email:rows[0].email,role:rows[0].role,created_at:rows[0].created_at},sid=randomUUID(),rt=refresh(u,sid);await pool.query("insert into sessions(id,user_id,refresh_token_hash,expires_at) values($1,$2,$3,now()+interval '30 days')",[sid,u.id,await argon2.hash(rt)]);setCookie(res,rt);res.json({accessToken:access(u),user:u})});
app.post("/api/v1/auth/refresh",async(req,res)=>{try{const t=req.cookies.prepos_refresh;if(!t)throw 0;const p=jwt.verify(t,process.env.JWT_REFRESH_SECRET,{issuer:"prepos-api",audience:"prepos-app"});const {rows}=await pool.query("select s.*,u.email,u.role,u.created_at from sessions s join users u on u.id=s.user_id where s.id=$1 and s.user_id=$2 and s.revoked_at is null and s.expires_at>now() and u.disabled=false",[p.sid,p.sub]);if(!rows[0]||!(await argon2.verify(rows[0].refresh_token_hash,t)))throw 0;const u={id:p.sub,email:rows[0].email,role:rows[0].role,created_at:rows[0].created_at},rt=refresh(u,rows[0].id);await pool.query("update sessions set refresh_token_hash=$1,last_used_at=now() where id=$2",[await argon2.hash(rt),rows[0].id]);setCookie(res,rt);res.json({accessToken:access(u),user:u})}catch(_e){res.clearCookie("prepos_refresh",{path:"/api/v1/auth"});res.status(401).json({error:{message:"Refresh session invalid"}})}});
app.post("/api/v1/auth/logout",async(req,res)=>{try{const t=req.cookies.prepos_refresh;if(t){const p=jwt.verify(t,process.env.JWT_REFRESH_SECRET,{issuer:"prepos-api",audience:"prepos-app"});await pool.query("update sessions set revoked_at=now() where id=$1 and user_id=$2",[p.sid,p.sub])}}catch(_e){}res.clearCookie("prepos_refresh",{path:"/api/v1/auth"});res.json({ok:true})});
app.get("/api/v1/auth/me",auth,(req,res)=>res.json({user:req.user}));
app.use("/api/v1",apiLimiter,auth);

app.get("/api/v1/sync/state",async(req,res)=>{const u=req.user.id;const [f,t,w,r,n,p]=await Promise.all([
 pool.query('select id,parent_id as "parentId",name,icon,color,sort_order as "sortOrder" from folders where user_id=$1 order by sort_order,created_at',[u]),
 pool.query('select id,folder_id as "folderId",name,content,revisions,sort_order as "sortOrder" from tests where user_id=$1 order by sort_order,created_at',[u]),
 pool.query("select data from wrong_questions where user_id=$1 order by updated_at desc",[u]),pool.query("select data from review_questions where user_id=$1 order by updated_at desc",[u]),
 pool.query("select data from notes where user_id=$1 order by updated_at desc",[u]),pool.query("select data from study_plans where user_id=$1 order by updated_at desc",[u])]);
 res.json({folders:f.rows,tests:t.rows,wrongQuestions:w.rows.map(x=>x.data),reviewQuestions:r.rows.map(x=>x.data),notes:n.rows.map(x=>x.data),studyPlans:p.rows.map(x=>x.data)})});
const state=z.object({folders:z.array(z.any()).max(5000),tests:z.array(z.any()).max(5000),wrongQuestions:z.array(z.any()).max(50000),reviewQuestions:z.array(z.any()).max(50000),notes:z.array(z.any()).max(50000),studyPlans:z.array(z.any()).max(50000)});
app.put("/api/v1/sync/state",async(req,res)=>{const p=state.safeParse(req.body);if(!p.success)return res.status(400).json({error:{message:"Invalid state payload"}});const c=await pool.connect();try{await c.query("begin");
 await c.query("delete from folders where user_id=$1",[req.user.id]);for(const [i,x] of p.data.folders.entries())await c.query("insert into folders(id,user_id,parent_id,name,icon,color,sort_order) values($1,$2,$3,$4,$5,$6,$7)",[String(x.id),req.user.id,x.parentId?String(x.parentId):null,String(x.name||"Folder"),x.icon||"📁",x.color||"#eff6ff",i]);
 await c.query("delete from tests where user_id=$1",[req.user.id]);for(const [i,x] of p.data.tests.entries())await c.query("insert into tests(id,user_id,folder_id,name,content,revisions,sort_order) values($1,$2,$3,$4,$5,$6,$7)",[String(x.id),req.user.id,x.folderId?String(x.folderId):null,String(x.name||"Test"),String(x.content||""),Number(x.revisions||0),i]);
 for(const tab of ["wrong_questions","review_questions","notes","study_plans"])await c.query(`delete from ${tab} where user_id=$1`,[req.user.id]);
 for(const x of p.data.wrongQuestions)await c.query("insert into wrong_questions(id,user_id,data) values($1,$2,$3)",[String(x.id||randomUUID()),req.user.id,x]);
 for(const x of p.data.reviewQuestions)await c.query("insert into review_questions(id,user_id,data) values($1,$2,$3)",[String(x.id||randomUUID()),req.user.id,x]);
 for(const x of p.data.notes)await c.query("insert into notes(id,user_id,data) values($1,$2,$3)",[String(x.id||randomUUID()),req.user.id,x]);
 for(const x of p.data.studyPlans)await c.query("insert into study_plans(id,user_id,data) values($1,$2,$3)",[String(x.id||randomUUID()),req.user.id,x]);
 await c.query("commit");res.json({ok:true})}catch(e){await c.query("rollback");console.error(e);res.status(500).json({error:{message:"State save failed"}})}finally{c.release()}});
app.get("/api/v1/intel/:key",async(req,res)=>{const {rows}=await pool.query("select data from intel where user_id=$1 and key_name=$2",[req.user.id,req.params.key]);res.json({data:rows[0]?.data??null})});
app.put("/api/v1/intel/:key",async(req,res)=>{if(!/^[A-Za-z0-9_.:-]{1,100}$/.test(req.params.key))return res.status(400).json({error:{message:"Invalid key"}});await pool.query(`insert into intel(user_id,key_name,data) values($1,$2,$3) on conflict(user_id,key_name) do update set data=excluded.data,updated_at=now()`,[req.user.id,req.params.key,req.body?.data??null]);res.json({ok:true})});
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:{message:"Internal server error"}})});
import fs from "node:fs/promises";
import path from "node:path";
async function initDb(){
  const schema=await fs.readFile(path.join(process.cwd(),"schema.sql"),"utf8");
  await pool.query(schema);
  console.log("PrepOS PostgreSQL schema ready");
}
initDb().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log(`PrepOS API listening on ${PORT}`)))
.catch(e=>{console.error("Database initialization failed",e);process.exit(1)});
