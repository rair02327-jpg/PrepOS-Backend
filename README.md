# PrepOS Production Backend

Architecture: WebIntoApp APK/WebView -> HTTPS -> Node/Express -> PostgreSQL.

### Included
- Email/password registration and login
- Argon2id password hashing
- 15-minute memory-only access JWT
- 30-day HttpOnly Secure refresh cookie + server-side session table
- Logout/session revocation
- Per-user cloud persistence
- Folders, HTML tests, wrong questions, review questions, notes, study plans
- Topper intelligence JSON state
- Helmet, CORS allowlist, rate limiting, Zod validation
- Docker/PostgreSQL deployment helpers

### Before APK build
Replace the placeholder API URL in `index.html`:
`https://YOUR-API-DOMAIN.example.com/api/v1`
with your real HTTPS API, or inject `window.PREPOS_API_BASE`.

### Deploy
1. Create PostgreSQL.
2. Run `schema.sql`.
3. Configure `.env`.
4. `npm install && npm start` or use Docker.
5. Put API behind HTTPS.
6. Add your WebIntoApp/web origin to `CORS_ORIGINS`.
7. Build the APK.

No localStorage or IndexedDB is used for persistent PrepOS data. Internet is required to sync/fetch cloud data.


# Render deployment — easiest path

Render can provision managed PostgreSQL and connect services to it. Keep the API and database in the same region when possible. citeturn0search0

## 1. Put this folder in GitHub
Create a GitHub repository and upload all files in this folder. Do NOT upload a real `.env` file or real secrets.

## 2. Create the Render services
Open Render and create a Blueprint from the repository. The included `render.yaml` creates:
- `prepos-api` — Node API
- `prepos-db` — PostgreSQL

Render supports Blueprint infrastructure-as-code and environment variables/secrets. citeturn0search9turn0search2

## 3. Set CORS_ORIGINS
In the API service's Environment section, set `CORS_ORIGINS` to the actual web origin(s) that will call the API. For an APK/WebView, if there is no normal HTTP Origin, the API code permits requests without an Origin header. Do not use `*` when credentials are enabled.

Keep `DATABASE_URL` and JWT secrets as Render environment variables, not in the HTML or Git repository. Render explicitly recommends environment variables for secrets and database connection strings. citeturn0search2

## 4. Wait for deployment
The API starts only after the PostgreSQL schema is initialized. Test:
`https://YOUR-API.onrender.com/api/v1/health`

Expected JSON contains `"ok":true` and `"database":"up"`.

## 5. Connect the APK
Open `index.html` and replace:
`https://YOUR-API-DOMAIN.example.com/api/v1`

with:
`https://YOUR-API.onrender.com/api/v1`

Then upload that `index.html` to WebIntoApp and rebuild the APK.

## 6. First launch
1. Open APK.
2. Create Account.
3. Login.
4. Import HTML tests.
5. Data is sent to PostgreSQL.
6. Install/open the APK on another phone.
7. Login with the same account.
8. The same cloud data is fetched.

## Important
The current design intentionally has no localStorage/IndexedDB persistence. If there is no internet, cloud data cannot be fetched or saved. This is the trade-off for making PostgreSQL the authoritative source of truth.
