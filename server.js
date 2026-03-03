require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const { analyzeUrl } = require('./ai/phishing-model');
const { lookupIP } = require('./ai/ip-intelligence');
const { analyzeEmail } = require('./ai/email-analyzer');

const app = express();
const PORT = process.env.PORT || 3000;

// Security and performance middlewares for production readiness
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// simple request logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}

// rate limiter to help mitigate basic abuse
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // limit each IP to 120 requests per windowMs
});
app.use('/api/', apiLimiter);

// serve static with reasonable caching for assets
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d', setHeaders: (res, filePath) => {
  if (filePath.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-cache');
  }
}}));

// Multer for .eml file uploads (memory storage)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ─────────────────────────────────────────────
// API: Phishing URL Analysis
// ─────────────────────────────────────────────
app.post('/api/phishing/analyze', (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'A valid URL string is required.' });
    }
    const result = analyzeUrl(url);
    res.json(result);
  } catch (err) {
    console.error('Phishing analysis error:', err);
    res.status(500).json({ error: 'Analysis failed.' });
  }
});

// ─────────────────────────────────────────────
// API: IP Intelligence Lookup
// ─────────────────────────────────────────────
app.post('/api/ip/lookup', async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip || typeof ip !== 'string') {
      return res.status(400).json({ error: 'A valid IP address string is required.' });
    }
    const result = await lookupIP(ip);
    res.json(result);
  } catch (err) {
    console.error('IP lookup error:', err);
    res.status(500).json({ error: 'IP lookup failed.' });
  }
});

// ─────────────────────────────────────────────
// API: Email Phishing Analysis (.eml upload)
// ─────────────────────────────────────────────
app.post('/api/email/analyze', upload.single('emlFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No .eml file uploaded.' });
    }
    const result = await analyzeEmail(req.file.buffer);
    res.json(result);
  } catch (err) {
    console.error('Email analysis error:', err);
    res.status(500).json({ error: 'Email analysis failed: ' + err.message });
  }
});

// ─────────────────────────────────────────────
// API: Live Threat Feed (simulated)
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// API: News feed (real via NewsAPI.org)
// ─────────────────────────────────────────────
// you'll need to supply the API key obtained from NewsAPI.org or similar
// prefer environment variable for secrets
const NEWS_API_KEY = process.env.NEWS_API_KEY || '5cd4d459870e433a8daaff9418ba01de';

// ensure fetch is available (Node 18+ has global fetch, otherwise use node-fetch)
let fetchFn = global.fetch;
if (!fetchFn) {
  try {
    fetchFn = require('node-fetch');
  } catch (err) {
    console.warn('node-fetch not installed; news endpoint may fail');
  }
}

app.get('/api/news', async (req, res) => {
  try {
    if (!fetchFn) throw new Error('No fetch available');
    const url = `https://newsapi.org/v2/top-headlines?language=en&pageSize=8&apiKey=${NEWS_API_KEY}`;
    const r = await fetchFn(url);
    const body = await r.json();
    let articles = body.articles || [];
    // fallback sample headlines when upstream API returns nothing
    const SAMPLE_HEADLINES = [
      { title: 'Zero-day exploit discovered in popular router firmware', url: '#' },
      { title: 'Major data breach affects millions of users', url: '#' },
      { title: 'AI model fooled by adversarial phishing email', url: '#' },
      { title: 'Cybersecurity firm releases new threat intelligence service', url: '#' },
      { title: 'Government issues warning about state-sponsored attacks', url: '#' },
      { title: 'Ransomware gang promises to stop targeting hospitals', url: '#' },
      { title: 'New malware family bypasses antivirus detection', url: '#' },
    ];
    if (!articles || !articles.length) {
      articles = SAMPLE_HEADLINES;
    }
    // Attempt to pick a sensible city for each article by matching known
    // city names in the title/source/description. If no match is found,
    // query Nominatim (OpenStreetMap) to geocode a best-effort location.
    const resolved = [];
    for (const a of articles) {
      try {
        const text = ((a.title || '') + ' ' + (a.source?.name || '') + ' ' + (a.description || '')).toLowerCase();
        let city = CITIES.find(c => text.includes(c.name.toLowerCase()));
        if (!city) city = CITIES.find(c => text.includes(c.name.split(' ')[0].toLowerCase()));

        let lat = null, lng = null;
        if (city) {
          lat = city.lat; lng = city.lng;
        } else {
          // fallback: try to geocode the article source name first, then the title
          const queryCandidates = [a.source?.name, a.title, a.description].filter(Boolean);
          for (const q of queryCandidates) {
            try {
              const nomUrl = `https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${encodeURIComponent(q)}`;
              const r = await fetchFn(nomUrl, { headers: { 'User-Agent': 'CHECK-IT/1.0 (contact@example.com)' } });
              const resJson = await r.json();
              if (Array.isArray(resJson) && resJson.length) {
                lat = parseFloat(resJson[0].lat);
                lng = parseFloat(resJson[0].lon);
                break;
              }
            } catch (e) {
              // ignore and try next candidate
            }
            // be kind to the free geocoder (slight pause)
            await new Promise(resolve => setTimeout(resolve, 150));
          }
        }

        // final fallback to random city
        if (lat === null || lng === null) {
          const fallback = CITIES[Math.floor(Math.random() * CITIES.length)];
          lat = fallback.lat; lng = fallback.lng;
        }

        resolved.push({ title: a.title, url: a.url, source: a.source?.name || '', lat, lng });
      } catch (err) {
        const fallback = CITIES[Math.floor(Math.random() * CITIES.length)];
        resolved.push({ title: a.title, url: a.url, source: a.source?.name || '', lat: fallback.lat, lng: fallback.lng });
      }
    }
    articles = resolved;
    console.log('[news] returning', articles.length, 'articles');
    res.json({ articles });
  } catch (err) {
    console.error('News API error:', err);
    // fallback to empty array
    console.log('[news] error, returning 0 articles');
    res.json({ articles: [] });
  }
});
const THREAT_TYPES = ['Phishing', 'Malware', 'DDoS', 'Brute Force', 'SQL Injection', 'XSS', 'Ransomware', 'C2 Beacon'];
const CITIES = [
  { name: 'Moscow', lat: 55.75, lng: 37.62 },
  { name: 'Beijing', lat: 39.91, lng: 116.40 },
  { name: 'São Paulo', lat: -23.55, lng: -46.63 },
  { name: 'Lagos', lat: 6.52, lng: 3.38 },
  { name: 'Mumbai', lat: 19.07, lng: 72.88 },
  { name: 'New York', lat: 40.71, lng: -74.00 },
  { name: 'London', lat: 51.51, lng: -0.13 },
  { name: 'Tokyo', lat: 35.68, lng: 139.69 },
  { name: 'Sydney', lat: -33.87, lng: 151.21 },
  { name: 'Berlin', lat: 52.52, lng: 13.41 },
  { name: 'Dubai', lat: 25.20, lng: 55.27 },
  { name: 'Toronto', lat: 43.65, lng: -79.38 },
  { name: 'Seoul', lat: 37.57, lng: 126.98 },
  { name: 'Johannesburg', lat: -26.20, lng: 28.05 },
  { name: 'Buenos Aires', lat: -34.60, lng: -58.38 },
  { name: 'Istanbul', lat: 41.01, lng: 28.98 },
  { name: 'Tehran', lat: 35.69, lng: 51.39 },
  { name: 'Jakarta', lat: -6.21, lng: 106.85 },
  { name: 'Mexico City', lat: 19.43, lng: -99.13 },
  { name: 'Cairo', lat: 30.04, lng: 31.24 },
];
const TARGETS = [
  { name: 'Washington D.C.', lat: 38.91, lng: -77.04 },
  { name: 'Silicon Valley', lat: 37.39, lng: -122.08 },
  { name: 'Frankfurt', lat: 50.11, lng: 8.68 },
  { name: 'Singapore', lat: 1.35, lng: 103.82 },
  { name: 'London', lat: 51.51, lng: -0.13 },
  { name: 'Tokyo', lat: 35.68, lng: 139.69 },
];

function generateThreat() {
  const source = CITIES[Math.floor(Math.random() * CITIES.length)];
  const target = TARGETS[Math.floor(Math.random() * TARGETS.length)];
  return {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    type: THREAT_TYPES[Math.floor(Math.random() * THREAT_TYPES.length)],
    severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
    source: { city: source.name, lat: source.lat, lng: source.lng },
    target: { city: target.name, lat: target.lat, lng: target.lng },
    timestamp: new Date().toISOString(),
  };
}

app.get('/api/threats/live', (req, res) => {
  const count = Math.floor(Math.random() * 6) + 5; // 5-10 threats per call
  const threats = Array.from({ length: count }, generateThreat);
  res.json({
    totalBlocked: Math.floor(Math.random() * 50000) + 120000,
    activeThreats: Math.floor(Math.random() * 300) + 100,
    threatsPerMinute: Math.floor(Math.random() * 80) + 40,
    threats,
  });
});

// ─────────────────────────────────────────────
// Serve SPA
// ─────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🛡️  CHECK-IT Server running on http://localhost:${PORT}\n`);
});
