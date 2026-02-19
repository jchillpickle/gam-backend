# Deploy Backend To Render (Step-by-Step)

This file is the exact deployment checklist for this backend.

## 1) Create a backend GitHub repo

Create a new repo (example: `gma-backend`) and upload these files from this folder:

- `server.js`
- `package.json`
- `package-lock.json`
- `.env.example`
- `.gitignore`
- `render.yaml`
- `README.md` (optional)

Do not upload `.env` or `node_modules`.

## 2) Create the Render web service

1. Go to `render.com` and sign in.
2. Click `New` -> `Web Service`.
3. Connect GitHub and select your backend repo.
4. Use these settings:
   - Environment: `Node`
   - Branch: `main`
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Health Check Path: `/health`

## 3) Add environment variables in Render

Use these keys in Render -> Environment:

- `API_KEY` = (generate a new one; do not reuse exposed keys)
- `ALLOWED_ORIGIN` = `https://jchillpickle.github.io,https://chill-pickle.com,https://www.chill-pickle.com`
- `STORE_PATH` = `./data/submissions.ndjson`
- `MIN_DURATION_MINUTES` = `8`
- `EMAIL_FROM` = `jason@larkinsrestaurants.com`
- `EMAIL_TO` = `jason@larkinsrestaurants.com`
- `EMAIL_CC` = (optional)
- `GOOGLE_CLIENT_EMAIL` = service account `client_email`
- `GOOGLE_PRIVATE_KEY` = service account `private_key` value (keep `\n` form)
- `GOOGLE_IMPERSONATED_USER` = `jason@larkinsrestaurants.com`

Generate an API key locally:

```bash
openssl rand -hex 24
```

## 4) Deploy and get backend URL

After deploy, copy your public URL, for example:

- `https://chill-pickle-gma-backend.onrender.com`

Health check should work at:

- `https://YOUR-RENDER-URL/health`

## 5) Connect frontend to backend

In your frontend repo (`gma-test`), edit `config.js`:

```js
window.GMA_CONFIG = {
  submitEndpoint: "https://YOUR-RENDER-URL/api/submissions",
  showCandidateScore: false
};
```

Commit/save, then wait for GitHub Pages to redeploy.

## 6) Live test

1. Open your public test page.
2. Submit a test candidate.
3. Confirm:
   - Candidate sees "Assessment Submitted"
   - You receive email result

## Notes

- On Render free tier, local file storage may be ephemeral; email is your primary durable output.
- Keep `.env` private and never commit service account keys.
