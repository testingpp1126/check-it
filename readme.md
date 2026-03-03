# CHECK-IT — Deployment Guide

This project is a 3D cybersecurity dashboard with IP intelligence, phishing analysis, and a globe that shows live threats and news.

## Quick start (local)

1. Copy `.env.example` to `.env` and set variables (at minimum `NEWS_API_KEY`).

2. Install dependencies:

```bash
npm install
```

3. Start the server:

```bash
npm start
```

4. Open http://localhost:3000 in your browser.

## Production notes

- Use `NEWS_API_KEY` environment variable to provide your NewsAPI key.
- The server includes security middlewares: `helmet`, `compression`, request logging, and rate limiting.
- Static assets are cached for 1 day; HTML is served with `no-cache` headers to ensure clients receive updates.

## Deployment

- For Heroku: create a `Procfile` with `web: node server.js`, set environment variables in Heroku dashboard, and `git push heroku main`.
- For Docker/k8s: create a Dockerfile (not included) that sets `NODE_ENV=production` and exposes `PORT`.

## Troubleshooting

- If news doesn't appear, check server logs for `[news] returning N articles` and browser console errors.
- Ensure your `NEWS_API_KEY` is valid and has quota.

## Files added

- `.env.example` — env var template
- `Procfile` — for Heroku
- `.gitignore` — common ignores

If you'd like, I can also add a `Dockerfile` and a basic `systemd` unit file.
