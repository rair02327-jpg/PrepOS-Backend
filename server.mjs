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

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 8080);
const isProd = process.env.NODE_ENV === "production";

for (const k of [
  "DATABASE_URL",
  "JWT_ACCESS_SECRET",
  "JWT_REFRESH_SECRET"
]) {
  if (!process.env[k]) {
    throw new Error(`Missing ${k}`);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "disable"
    ? false
    : { rejectUnauthorized: false },
  max: Number(process.env.DB_POOL_MAX || 10),
});

app.set("trust proxy", 1);

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(express.json({ limit: "25mb" }));
app.use(cookieParser());

/* =========================================================
   CORS
   ========================================================= */

const origins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

/*
  WebIntoApp packages local HTML inside Android WebView.
  Such requests may use Origin: null.

  We allow:
  - no Origin
  - Origin: null
  - origins explicitly listed in CORS_ORIGINS
*/

const corsOrigin = (origin, callback) => {
  if (
    !origin ||
    origin === "null" ||
    origins.includes(origin)
  ) {
    return callback(null, true);
  }

  return callback(new Error("CORS origin not allowed"));
};

/* =========================================================
   HEALTH CHECK
   IMPORTANT: This MUST be BEFORE CORS middleware.
   Render health checks must never be blocked by CORS.
   ========================================================= */

app.get("/api/v1/health", async (_req, res) => {
  try {
    await pool.query("select 1");

    res.status(200).json({
      ok: true,
      database: "up",
      time: new Date().toISOString()
    });
  } catch (_error) {
    res.status(503).json({
      ok: false,
      database: "down"
    });
  }
});

/* =========================================================
   CORS MIDDLEWARE
   ========================================================= */

app.use(
  cors({
    origin: corsOrigin,
    credentials: true,
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

/* =========================================================
   RATE LIMITING
   ========================================================= */

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false
});

/* =========================================================
   JWT
   ========================================================= */

const access = (u) =>
  jwt.sign(
    {
      sub: u.id,
      role: u.role
    },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: "15m",
      issuer: "prepos-api",
      audience: "prepos-app"
    }
  );

const refresh = (u, sid) =>
  jwt.sign(
    {
      sub: u.id,
      sid
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: "30d",
      issuer: "prepos-api",
      audience: "prepos-app"
    }
  );

/* =========================================================
   REFRESH COOKIE
   WebIntoApp cross-origin WebView compatibility:
   SameSite=None + Secure
   ========================================================= */

const setCookie = (res, token) => {
  res.cookie(
    "prepos_refresh",
    token,
    {
      httpOnly: true,
      secure: isProd,
      sameSite: "none",
      path: "/api/v1/auth",
      maxAge: 30 * 86400000
    }
  );
};

/* =========================================================
   AUTH MIDDLEWARE
   ========================================================= */

async function auth(req, res, next) {
  try {
    const header = req.get("authorization") || "";

    if (!header.startsWith("Bearer ")) {
      throw 0;
    }

    const payload = jwt.verify(
      header.slice(7),
      process.env.JWT_ACCESS_SECRET,
      {
        issuer: "prepos-api",
        audience: "prepos-app"
      }
    );

    const { rows } = await pool.query(
      `select id,email,role,created_at
       from users
       where id=$1 and disabled=false`,
      [payload.sub]
    );

    if (!rows[0]) {
      throw 0;
    }

    req.user = rows[0];
    next();

  } catch (_error) {
    res.status(401).json({
      error: {
        message: "Authentication required"
      }
    });
  }
}

/* =========================================================
   VALIDATION
   ========================================================= */

const creds = z.object({
  email: z.string().email().max(320),
  password: z.string().min(8).max(128)
});

/* =========================================================
   AUTH ROUTES
   ========================================================= */

app.use("/api/v1/auth", authLimiter);

/* REGISTER */

app.post("/api/v1/auth/register", async (req, res) => {
  const parsed = creds.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: {
        message: "Valid email and password are required"
      }
    });
  }

  try {
    const email = parsed.data.email
      .toLowerCase()
      .trim();

    const hash = await argon2.hash(
      parsed.data.password,
      {
        type: argon2.argon2id
      }
    );

    const id = randomUUID();
    const client = await pool.connect();

    try {
      await client.query("begin");

      const { rows } = await client.query(
        `insert into users
        (id,email,password_hash)
        values($1,$2,$3)
        returning id,email,role,created_at`,
        [
          id,
          email,
          hash
        ]
      );

      const user = rows[0];
      const sid = randomUUID();
      const refreshToken = refresh(user, sid);

      await client.query(
        `insert into sessions
        (id,user_id,refresh_token_hash,expires_at)
        values($1,$2,$3,now()+interval '30 days')`,
        [
          sid,
          id,
          await argon2.hash(refreshToken)
        ]
      );

      await client.query("commit");

      setCookie(res, refreshToken);

      res.status(201).json({
        accessToken: access(user),
        user
      });

    } catch (e) {
      await client.query("rollback");

      if (e.code === "23505") {
        return res.status(409).json({
          error: {
            message: "Email already registered"
          }
        });
      }

      throw e;

    } finally {
      client.release();
    }

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: {
        message: "Registration failed"
      }
    });
  }
});

/* LOGIN */

app.post("/api/v1/auth/login", async (req, res) => {
  const parsed = creds.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: {
        message: "Valid email and password are required"
      }
    });
  }

  const { rows } = await pool.query(
    `select id,email,role,password_hash,created_at
     from users
     where email=$1 and disabled=false`,
    [
      parsed.data.email
        .toLowerCase()
        .trim()
    ]
  );

  if (
    !rows[0] ||
    !(await argon2.verify(
      rows[0].password_hash,
      parsed.data.password
    ))
  ) {
    return res.status(401).json({
      error: {
        message: "Invalid email or password"
      }
    });
  }

  const user = {
    id: rows[0].id,
    email: rows[0].email,
    role: rows[0].role,
    created_at: rows[0].created_at
  };

  const sid = randomUUID();
  const refreshToken = refresh(user, sid);

  await pool.query(
    `insert into sessions
    (id,user_id,refresh_token_hash,expires_at)
    values($1,$2,$3,now()+interval '30 days')`,
    [
      sid,
      user.id,
      await argon2.hash(refreshToken)
    ]
  );

  setCookie(res, refreshToken);

  res.json({
    accessToken: access(user),
    user
  });
});

/* REFRESH */

app.post("/api/v1/auth/refresh", async (req, res) => {
  try {
    const token = req.cookies.prepos_refresh;

    if (!token) {
      throw 0;
    }

    const payload = jwt.verify(
      token,
      process.env.JWT_REFRESH_SECRET,
      {
        issuer: "prepos-api",
        audience: "prepos-app"
      }
    );

    const { rows } = await pool.query(
      `select s.*,u.email,u.role,u.created_at
       from sessions s
       join users u on u.id=s.user_id
       where s.id=$1
       and s.user_id=$2
       and s.revoked_at is null
       and s.expires_at>now()
       and u.disabled=false`,
      [
        payload.sid,
        payload.sub
      ]
    );

    if (
      !rows[0] ||
      !(await argon2.verify(
        rows[0].refresh_token_hash,
        token
      ))
    ) {
      throw 0;
    }

    const user = {
      id: payload.sub,
      email: rows[0].email,
      role: rows[0].role,
      created_at: rows[0].created_at
    };

    const refreshToken = refresh(
      user,
      rows[0].id
    );

    await pool.query(
      `update sessions
       set refresh_token_hash=$1,
           last_used_at=now()
       where id=$2`,
      [
        await argon2.hash(refreshToken),
        rows[0].id
      ]
    );

    setCookie(res, refreshToken);

    res.json({
      accessToken: access(user),
      user
    });

  } catch (_error) {

    res.clearCookie(
      "prepos_refresh",
      {
        path: "/api/v1/auth"
      }
    );

    res.status(401).json({
      error: {
        message: "Refresh session invalid"
      }
    });
  }
});

/* LOGOUT */

app.post("/api/v1/auth/logout", async (req, res) => {
  try {
    const token = req.cookies.prepos_refresh;

    if (token) {
      const payload = jwt.verify(
        token,
        process.env.JWT_REFRESH_SECRET,
        {
          issuer: "prepos-api",
          audience: "prepos-app"
        }
      );

      await pool.query(
        `update sessions
         set revoked_at=now()
         where id=$1 and user_id=$2`,
        [
          payload.sid,
          payload.sub
        ]
      );
    }

  } catch (_error) {}

  res.clearCookie(
    "prepos_refresh",
    {
      path: "/api/v1/auth"
    }
  );

  res.json({
    ok: true
  });
});

/* CURRENT USER */

app.get(
  "/api/v1/auth/me",
  auth,
  (req, res) =>
    res.json({
      user: req.user
    })
);

/* =========================================================
   PROTECTED API
   ========================================================= */

app.use(
  "/api/v1",
  apiLimiter,
  auth
);

/* =========================================================
   SYNC STATE - GET
   ========================================================= */

app.get(
  "/api/v1/sync/state",
  async (req, res) => {

    const userId = req.user.id;

    const [
      folders,
      tests,
      wrongQuestions,
      reviewQuestions,
      notes,
      studyPlans
    ] = await Promise.all([

      pool.query(
        `select
          id,
          parent_id as "parentId",
          name,
          icon,
          color,
          sort_order as "sortOrder"
         from folders
         where user_id=$1
         order by sort_order,created_at`,
        [userId]
      ),

      pool.query(
        `select
          id,
          folder_id as "folderId",
          name,
          content,
          revisions,
          sort_order as "sortOrder"
         from tests
         where user_id=$1
         order by sort_order,created_at`,
        [userId]
      ),

      pool.query(
        `select data
         from wrong_questions
         where user_id=$1
         order by updated_at desc`,
        [userId]
      ),

      pool.query(
        `select data
         from review_questions
         where user_id=$1
         order by updated_at desc`,
        [userId]
      ),

      pool.query(
        `select data
         from notes
         where user_id=$1
         order by updated_at desc`,
        [userId]
      ),

      pool.query(
        `select data
         from study_plans
         where user_id=$1
         order by updated_at desc`,
        [userId]
      )
    ]);

    res.json({
      folders: folders.rows,
      tests: tests.rows,
      wrongQuestions:
        wrongQuestions.rows.map(x => x.data),
      reviewQuestions:
        reviewQuestions.rows.map(x => x.data),
      notes:
        notes.rows.map(x => x.data),
      studyPlans:
        studyPlans.rows.map(x => x.data)
    });
  }
);

/* =========================================================
   STATE VALIDATION
   ========================================================= */

const state = z.object({
  folders: z.array(z.any()).max(5000),
  tests: z.array(z.any()).max(5000),
  wrongQuestions: z.array(z.any()).max(50000),
  reviewQuestions: z.array(z.any()).max(50000),
  notes: z.array(z.any()).max(50000),
  studyPlans: z.array(z.any()).max(50000)
});

/* =========================================================
   SYNC STATE - PUT
   ========================================================= */

app.put(
  "/api/v1/sync/state",
  async (req, res) => {

    const parsed = state.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: {
          message: "Invalid state payload"
        }
      });
    }

    const client = await pool.connect();

    try {

      await client.query("begin");

      /* FOLDERS */

      await client.query(
        "delete from folders where user_id=$1",
        [req.user.id]
      );

      for (
        const [index, item]
        of parsed.data.folders.entries()
      ) {

        await client.query(
          `insert into folders
          (id,user_id,parent_id,name,icon,color,sort_order)
          values($1,$2,$3,$4,$5,$6,$7)`,
          [
            String(item.id),
            req.user.id,
            item.parentId
              ? String(item.parentId)
              : null,
            String(item.name || "Folder"),
            item.icon || "📁",
            item.color || "#eff6ff",
            index
          ]
        );
      }

      /* TESTS */

      await client.query(
        "delete from tests where user_id=$1",
        [req.user.id]
      );

      for (
        const [index, item]
        of parsed.data.tests.entries()
      ) {

        await client.query(
          `insert into tests
          (id,user_id,folder_id,name,content,revisions,sort_order)
          values($1,$2,$3,$4,$5,$6,$7)`,
          [
            String(item.id),
            req.user.id,
            item.folderId
              ? String(item.folderId)
              : null,
            String(item.name || "Test"),
            String(item.content || ""),
            Number(item.revisions || 0),
            index
          ]
        );
      }

      /* OTHER TABLES */

      for (
        const table
        of [
          "wrong_questions",
          "review_questions",
          "notes",
          "study_plans"
        ]
      ) {
        await client.query(
          `delete from ${table} where user_id=$1`,
          [req.user.id]
        );
      }

      /* WRONG QUESTIONS */

      for (const item of parsed.data.wrongQuestions) {
        await client.query(
          `insert into wrong_questions
          (id,user_id,data)
          values($1,$2,$3)`,
          [
            String(item.id || randomUUID()),
            req.user.id,
            item
          ]
        );
      }

      /* REVIEW QUESTIONS */

      for (const item of parsed.data.reviewQuestions) {
        await client.query(
          `insert into review_questions
          (id,user_id,data)
          values($1,$2,$3)`,
          [
            String(item.id || randomUUID()),
            req.user.id,
            item
          ]
        );
      }

      /* NOTES */

      for (const item of parsed.data.notes) {
        await client.query(
          `insert into notes
          (id,user_id,data)
          values($1,$2,$3)`,
          [
            String(item.id || randomUUID()),
            req.user.id,
            item
          ]
        );
      }

      /* STUDY PLANS */

      for (const item of parsed.data.studyPlans) {
        await client.query(
          `insert into study_plans
          (id,user_id,data)
          values($1,$2,$3)`,
          [
            String(item.id || randomUUID()),
            req.user.id,
            item
          ]
        );
      }

      await client.query("commit");

      res.json({
        ok: true
      });

    } catch (e) {

      await client.query("rollback");

      console.error(e);

      res.status(500).json({
        error: {
          message: "State save failed"
        }
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   INTELLIGENCE DATA
   ========================================================= */

app.get(
  "/api/v1/intel/:key",
  async (req, res) => {

    const { rows } = await pool.query(
      `select data
       from intel
       where user_id=$1
       and key_name=$2`,
      [
        req.user.id,
        req.params.key
      ]
    );

    res.json({
      data: rows[0]?.data ?? null
    });
  }
);

app.put(
  "/api/v1/intel/:key",
  async (req, res) => {

    if (
      !/^[A-Za-z0-9_.:-]{1,100}$/
        .test(req.params.key)
    ) {
      return res.status(400).json({
        error: {
          message: "Invalid key"
        }
      });
    }

    await pool.query(
      `insert into intel
      (user_id,key_name,data)
      values($1,$2,$3)
      on conflict(user_id,key_name)
      do update set
        data=excluded.data,
        updated_at=now()`,
      [
        req.user.id,
        req.params.key,
        req.body?.data ?? null
      ]
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   GLOBAL ERROR HANDLER
   ========================================================= */

app.use(
  (err, _req, res, _next) => {
    console.error(err);

    res.status(500).json({
      error: {
        message: "Internal server error"
      }
    });
  }
);

/* =========================================================
   DATABASE INITIALIZATION + SERVER
   ========================================================= */

import fs from "node:fs/promises";
import path from "node:path";

async function initDb() {

  const schema = await fs.readFile(
    path.join(
      process.cwd(),
      "schema.sql"
    ),
    "utf8"
  );

  await pool.query(schema);

  console.log(
    "PrepOS PostgreSQL schema ready"
  );
}

initDb()
  .then(() =>
    app.listen(
      PORT,
      "0.0.0.0",
      () =>
        console.log(
          `PrepOS API listening on ${PORT}`
        )
    )
  )
  .catch(e => {
    console.error(
      "Database initialization failed",
      e
    );

    process.exit(1);
  });
