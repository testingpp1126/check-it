/**
 * CyberShield — Frontend Application Logic
 * Handles API calls, UI updates, live threat feed, phishing analysis,
 * and the full-screen IP Intelligence panel with Leaflet map.
 */

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const liveClock = $('#live-clock');
  const statIP = $('#stat-ip');
  const statISP = $('#stat-isp');
  const statUptime = $('#stat-uptime');
  const statScans = $('#stat-scans');
  const threatFeed = $('#threat-feed');
  const themeToggleBtn = $('#theme-toggle');

  // theme handling -------------------------------------------------------
  function applyTheme(theme) {
    document.body.classList.toggle('light', theme === 'light');
    if (themeToggleBtn) themeToggleBtn.textContent = theme === 'light' ? '🌙' : '☀️';
  }
  function initTheme() {
    let stored = localStorage.getItem('theme');
    if (!stored) {
      // default to dark but respect system preference if available
      stored = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    applyTheme(stored);
    if (themeToggleBtn) {
      themeToggleBtn.addEventListener('click', () => {
        const newTheme = document.body.classList.contains('light') ? 'dark' : 'light';
        applyTheme(newTheme);
        localStorage.setItem('theme', newTheme);
      });
    }
  }
  initTheme();

  // track when application started so we can show uptime
  const appStart = new Date();

  let scansToday = 0;
  let ipMap = null; // Leaflet map instance
  let ipMarker = null;

  // ═══════════════ CLOCK ═══════════════
  function updateClock() {
    const now = new Date();
    liveClock.textContent = [now.getHours(), now.getMinutes(), now.getSeconds()]
      .map(v => String(v).padStart(2, '0')).join(':');
  }
  setInterval(updateClock, 1000);
  updateClock();

  // ═══════════════ PARTICLES ═══════════════
  (function spawnParticles() {
    const container = $('#particles');
    for (let i = 0; i < 40; i++) {
      const p = document.createElement('div');
      p.className = 'particle';
      p.style.left = Math.random() * 100 + '%';
      p.style.animationDuration = (8 + Math.random() * 15) + 's';
      p.style.animationDelay = (Math.random() * 10) + 's';
      const s = (1 + Math.random() * 2) + 'px';
      p.style.width = s; p.style.height = s;
      container.appendChild(p);
    }
  })();

  // ═══════════════ ANIMATED COUNTER ═══════════════
  function animateValue(el, start, end, duration) {
    const t0 = performance.now();
    function tick(now) {
      const p = Math.min((now - t0) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.floor(start + (end - start) * eased).toLocaleString();
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // ═══════════════ LIVE THREAT FEED ═══════════════
  async function fetchLiveThreats() {
    try {
      const res = await fetch('/api/threats/live');
      const data = await res.json();
      // we still plot the globe/threat feed but we no longer update the
      // top stats since they're repurposed for IP/ISP/uptime.

      data.threats.forEach((t, i) => {
        setTimeout(() => {
          if (CyberGlobe.isReady) {
            CyberGlobe.addThreatMarker(t.source.lat, t.source.lng, t.severity, t.type);
            CyberGlobe.addArc(t.source.lat, t.source.lng, t.target.lat, t.target.lng, t.severity);
          }
          const item = document.createElement('div');
          item.className = 'threat-feed-item';
          const ts = new Date(t.timestamp);
          const timeStr = [ts.getHours(), ts.getMinutes(), ts.getSeconds()].map(v => String(v).padStart(2, '0')).join(':');
          item.innerHTML = `
            <span class="severity ${t.severity}"></span>
            <span class="type">${t.type}</span>
            <span class="route">${t.source.city} → ${t.target.city}</span>
            <span class="time">${timeStr}</span>`;
          threatFeed.prepend(item);
          while (threatFeed.children.length > 30) threatFeed.removeChild(threatFeed.lastChild);
        }, i * 300);
      });
    } catch (err) {
      console.warn('Threat feed error:', err);
    }
  }
  fetchLiveThreats();
  setInterval(fetchLiveThreats, 5000);

  // ═══════════════ NEWS TICKER ═══════════════
  let newsQueue = [];

  function renderNewsList(articles) {
    const container = $('#news-items');
    if (!container) return;
    container.innerHTML = articles.map(a =>
      `<div class="news-item">${a.title}</div>`
    ).join('');

    // attach click handlers to news items: focus on globe then open link
    Array.from(container.querySelectorAll('.news-item')).forEach((el, i) => {
      const art = articles[i];
      el.style.cursor = 'pointer';
      el.addEventListener('click', (ev) => {
        ev.preventDefault();
        if (window.CyberGlobe && CyberGlobe.isReady) {
          CyberGlobe.focusOn(art.lat, art.lng);
          setTimeout(() => { if (art.url) window.open(art.url, '_blank'); }, 800);
        } else {
          if (art.url) window.open(art.url, '_blank');
        }
      });
    });
  }

  async function fetchNews() {
    try {
      const res = await fetch('/api/news');
      const data = await res.json();
      const articles = (data.articles || []).map(a => ({ title: a.title, url: a.url, lat: a.lat, lng: a.lng }));
      newsQueue = articles;
      renderNewsList(articles);

      // If the globe is ready, clear and add markers immediately
      if (window.CyberGlobe && CyberGlobe.isReady) {
        CyberGlobe.clearNewsMarkers && CyberGlobe.clearNewsMarkers();
        articles.forEach(a => { if (a.lat && a.lng) CyberGlobe.addNewsMarker(a.lat, a.lng, a.title, a.url); });
      }
    } catch (err) {
      console.warn('News fetch error:', err);
    }
  }

  // If globe initializes after first fetch, add queued articles
  function tryApplyQueuedNews() {
    if (newsQueue.length && window.CyberGlobe && CyberGlobe.isReady) {
      CyberGlobe.clearNewsMarkers && CyberGlobe.clearNewsMarkers();
      newsQueue.forEach(a => { if (a.lat && a.lng) CyberGlobe.addNewsMarker(a.lat, a.lng, a.title, a.url); });
    }
  }

  // also run when globe dispatches ready event
  window.addEventListener('cyberglobe:ready', () => {
    tryApplyQueuedNews();
  });

  fetchNews();
  setInterval(fetchNews, 60000);
  // poll briefly to apply queued news once globe becomes ready
  const newsApplyInterval = setInterval(() => {
    tryApplyQueuedNews();
  }, 1000);
  setTimeout(() => clearInterval(newsApplyInterval), 20000);

  // expose a small health-check for readiness
  window.appReady = () => ({ globe: window.CyberGlobe?.isReady === true });

  // ═══════════════ UPTIME COUNTER ═══════════════
  function updateUptime() {
    const now = new Date();
    const diff = Math.floor((now - appStart) / 1000);
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    const s = diff % 60;
    // format as HH:MM:SS for readability
    statUptime.textContent = [h, m, s].map(v => String(v).padStart(2, '0')).join(':');
  }
  setInterval(updateUptime, 1000);
  updateUptime();

  // ═══════════════ AUTOMATIC CLIENT IP/ISP POPULATION ═══════════════
  async function populateSelfIP() {
    try {
      // use external service to get public IP
      const ipResp = await fetch('https://api.ipify.org?format=json');
      const ipData = await ipResp.json();
      const ip = ipData.ip;
      if (ip) {
        statIP.textContent = ip;
        // perform lookup to fetch ISP info but do not increment scans counter
        const res = await fetch('/api/ip/lookup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
        const data = await res.json();
        statISP.textContent = data.networkInfo?.isp || data.geolocation?.isp || 'N/A';
      }
    } catch (err) {
      console.warn('Automatic IP/ISP fetch failed:', err);
    }
  }
  populateSelfIP();

  // ═══════════════ PHISHING DETECTOR ═══════════════
  const phishingForm = $('#phishing-form');
  const phishingInput = $('#phishing-input');
  const phishingBtn = $('#phishing-btn');
  const phishingResult = $('#phishing-result');

  phishingForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = phishingInput.value.trim();
    if (!url) return;
    setLoading(phishingBtn, true);
    phishingResult.hidden = true;
    try {
      const res = await fetch('/api/phishing/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
      const data = await res.json();
      scansToday++; statScans.textContent = scansToday;
      renderPhishingResult(data);
    } catch {
      phishingResult.innerHTML = `<div class="recommendation"><span class="rec-icon">❌</span><span>Analysis failed.</span></div>`;
      phishingResult.hidden = false;
    } finally {
      setLoading(phishingBtn, false);
    }
  });

  function setLoading(btn, loading) {
    btn.querySelector('.btn-text').hidden = loading;
    btn.querySelector('.btn-loader').hidden = !loading;
    btn.disabled = loading;
  }

  function renderPhishingResult(data) {
    const C = 2 * Math.PI * 34;
    const offset = C - (data.riskScore / 100) * C;
    const color = data.color || '#00f0ff';
    let featHTML = '';
    if (data.features?.length) {
      featHTML = '<div class="feature-list">' + data.features.slice(0, 6).map(f => {
        const fc = f.score > 12 ? '#ff4444' : f.score > 6 ? '#ffaa00' : '#00ff88';
        return `<div class="feature-item" style="border-left-color:${fc}"><span class="feature-name">${f.name} (+${f.score})</span><span class="feature-detail">${f.detail}</span></div>`;
      }).join('') + '</div>';
    }
    let recsHTML = '';
    if (data.recommendations?.length) {
      recsHTML = '<div class="recommendations">' + data.recommendations.map(r =>
        `<div class="recommendation"><span class="rec-icon">⚡</span><span>${r}</span></div>`).join('') + '</div>';
    }
    phishingResult.innerHTML = `
      <div class="risk-meter">
        <div class="risk-circle">
          <svg viewBox="0 0 80 80"><circle class="track" cx="40" cy="40" r="34"/><circle class="progress" cx="40" cy="40" r="34" stroke="${color}" stroke-dasharray="${C}" stroke-dashoffset="${offset}"/></svg>
          <div class="risk-score-text"><span class="risk-score-number" style="color:${color}">${data.riskScore}</span><span class="risk-score-label">/ 100</span></div>
        </div>
        <div class="risk-info"><h3 style="color:${color}">${data.riskLevel.toUpperCase()}</h3><p>${data.summary}</p></div>
      </div>${featHTML}${recsHTML}`;
    phishingResult.hidden = false;
  }

  // ═══════════════ IP INTELLIGENCE ═══════════════
  const ipForm = $('#ip-form');
  const ipInput = $('#ip-input');
  const ipBtn = $('#ip-btn');
  const ipFullscreen = $('#ip-fullscreen');
  const ipCloseBtn = $('#ip-close-btn');

  ipForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = ipInput.value.trim();
    if (!ip) return;
    setLoading(ipBtn, true);
    try {
      const res = await fetch('/api/ip/lookup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
      const data = await res.json();
      scansToday++; statScans.textContent = scansToday;
      // update headline stats with IP information
      statIP.textContent = data.ip || 'N/A';
      statISP.textContent = data.networkInfo?.isp || data.geolocation?.isp || 'N/A';
      renderIPFullscreen(data);
    } catch {
      alert('IP lookup failed. Check server connection.');
    } finally {
      setLoading(ipBtn, false);
    }
  });

  ipCloseBtn.addEventListener('click', () => {
    ipFullscreen.hidden = true;
    document.body.style.overflow = '';
  });

  function renderIPFullscreen(data) {
    if (data.error && !data.geolocation) {
      alert(data.error);
      return;
    }

    // Show fullscreen
    ipFullscreen.hidden = false;
    document.body.style.overflow = 'hidden';
    $('#ip-queried-ip').textContent = data.ip;

    const geo = data.geolocation || {};
    const net = data.networkInfo || {};
    const ttl = data.ttl || {};
    const vpn = data.vpn || {};
    const networkType = data.networkType || {};
    const riskFactor = data.riskFactor || {};
    const color = data.threatColor || '#00f0ff';

    // ── Risk Overview ──
    const C = 2 * Math.PI * 42;
    const offset = C - ((riskFactor.riskScore || 0) / 100) * C;
    $('#ip-risk-overview').innerHTML = `
      <div class="card-header"><span class="card-icon">🛡️</span><span class="card-title">THREAT ASSESSMENT</span></div>
      <div class="risk-overview-content">
        <div class="risk-circle-lg">
          <svg viewBox="0 0 100 100"><circle class="track" cx="50" cy="50" r="42"/><circle class="progress" cx="50" cy="50" r="42" stroke="${color}" stroke-dasharray="${C}" stroke-dashoffset="${offset}"/></svg>
          <div class="risk-score-text"><span class="risk-score-number" style="color:${color}">${riskFactor.riskScore || 0}</span><span class="risk-score-label">/ 100</span></div>
        </div>
        <div class="risk-overview-info">
          <h3 style="color:${color}">${(riskFactor.riskRating || 'unknown').toUpperCase()} RISK</h3>
          <p>${data.summary || ''}</p>
          <p style="margin-top:6px;color:var(--text-dim)">Analyzed at ${new Date(data.analyzedAt).toLocaleString()}</p>
        </div>
      </div>`;

    // ── VPN / Proxy / Tor ──
    const vpnStatus = vpn.vpnDetected ? 'danger' : 'safe';
    const proxyStatus = vpn.proxyDetected ? 'danger' : 'safe';
    const torStatus = vpn.torDetected ? 'critical' : 'safe';
    $('#ip-vpn-card').innerHTML = `
      <div class="card-header"><span class="card-icon">🔐</span><span class="card-title">VPN / PROXY</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">VPN Detected</span><span class="status-badge ${vpnStatus}">${vpn.vpnDetected ? '⚠ YES' : '✓ NO'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Proxy Detected</span><span class="status-badge ${proxyStatus}">${vpn.proxyDetected ? '⚠ YES' : '✓ NO'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Tor Exit Node</span><span class="status-badge ${torStatus}">${vpn.torDetected ? '🔴 YES' : '✓ NO'}</span></div>
      ${vpn.provider ? `<div class="ip-kv-row"><span class="ip-kv-label">Provider</span><span class="ip-kv-value cyan">${vpn.provider}</span></div>` : ''}
      <div class="ip-kv-row"><span class="ip-kv-label">Confidence</span><span class="ip-kv-value">${(vpn.confidence || 'N/A').toUpperCase()}</span></div>`;

    // ── Network Type ──
    $('#ip-network-card').innerHTML = `
      <div class="card-header"><span class="card-icon">${networkType.icon || '🌐'}</span><span class="card-title">NETWORK</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Network Type</span><span class="ip-kv-value cyan">${networkType.type || 'Unknown'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Risk Level</span><span class="ip-kv-value ${networkType.risk === 'elevated' ? 'yellow' : 'green'}">${(networkType.risk || 'N/A').toUpperCase()}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">ISP</span><span class="ip-kv-value">${net.isp || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Organization</span><span class="ip-kv-value">${net.org || '—'}</span></div>`;

    // ── TTL & OS ──
    $('#ip-ttl-card').innerHTML = `
      <div class="card-header"><span class="card-icon">🖥️</span><span class="card-title">TTL / OS</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Initial TTL</span><span class="ip-kv-value cyan">${ttl.initialTTL || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Observed TTL</span><span class="ip-kv-value">${ttl.observedTTL || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Hops</span><span class="ip-kv-value">${ttl.hops || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">OS Hint</span><span class="ip-kv-value green">${ttl.osGuess || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Confidence</span><span class="ip-kv-value">${(ttl.confidence || 'N/A').toUpperCase()}</span></div>`;

    // ── ASN ──
    $('#ip-asn-card').innerHTML = `
      <div class="card-header"><span class="card-icon">📊</span><span class="card-title">ASN INFO</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">ASN Number</span><span class="ip-kv-value cyan">${net.asnNumber || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">ASN Name</span><span class="ip-kv-value">${net.asnName || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Mobile</span><span class="ip-kv-value">${net.mobile ? 'Yes' : 'No'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Hosting</span><span class="ip-kv-value ${net.hosting ? 'yellow' : ''}">${net.hosting ? 'Yes' : 'No'}</span></div>`;

    // ── Risk Factors ──
    const factors = riskFactor.factors || [];
    let factorsHTML = '<div class="card-header"><span class="card-icon">⚡</span><span class="card-title">RISK FACTORS</span></div>';
    if (factors.length === 0) {
      factorsHTML += '<div class="ip-kv-row"><span class="ip-kv-label">No risk factors identified</span><span class="status-badge safe">✓ CLEAN</span></div>';
    } else {
      factorsHTML += factors.map(f =>
        `<div class="risk-factor-item ${f.impact}"><span class="risk-factor-label">${f.label}</span><span class="risk-factor-impact status-badge ${f.impact}">${f.impact.toUpperCase()} +${f.score}</span></div>`
      ).join('');
    }
    $('#ip-risk-factors-card').innerHTML = factorsHTML;

    // ── Network Details ──
    $('#ip-details-card').innerHTML = `
      <div class="card-header"><span class="card-icon">📍</span><span class="card-title">DETAILS</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Country</span><span class="ip-kv-value">${geo.country || '—'} ${geo.countryCode ? `(${geo.countryCode})` : ''}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Region</span><span class="ip-kv-value">${geo.region || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">City</span><span class="ip-kv-value">${geo.city || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">ZIP</span><span class="ip-kv-value">${geo.zip || '—'}</span></div>
      <div class="ip-kv-row"><span class="ip-kv-label">Timezone</span><span class="ip-kv-value">${geo.timezone || '—'}</span></div>`;

    // ── Tags ──
    const tags = data.tags || [];
    const tagClass = (t) => {
      if (['proxy', 'vpn', 'tor', 'known-threat-range', 'anonymizer'].includes(t)) return 'danger';
      if (['hosting-provider', 'high-risk-country'].includes(t)) return 'warning';
      if (['mobile', 'private', 'internal'].includes(t)) return 'info';
      return 'safe';
    };
    $('#ip-tags-full').innerHTML = tags.map(t =>
      `<span class="ip-tag-full ${tagClass(t)}">${t.toUpperCase()}</span>`
    ).join('');

    // ── Location bar ──
    $('#ip-location-bar').innerHTML = `
      <div class="ip-loc-item"><span class="ip-loc-label">CITY</span><span class="ip-loc-value">${geo.city || '—'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">COUNTRY</span><span class="ip-loc-value">${geo.country || '—'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">COORDINATES</span><span class="ip-loc-value">${geo.lat || '—'}, ${geo.lng || '—'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">TIMEZONE</span><span class="ip-loc-value">${geo.timezone || '—'}</span></div>`;

    // ── Leaflet Map ──
    initIPMap(geo.lat, geo.lng, data.ip, geo.city, geo.country);

    // ── Globe marker ──
    if (CyberGlobe.isReady && geo.lat && geo.lng) {
      CyberGlobe.addThreatMarker(geo.lat, geo.lng, data.threatLevel, 'lookup');
    }
  }

  // ═══════════════ LEAFLET MAP ═══════════════
  function initIPMap(lat, lng, ip, city, country) {
    const container = document.getElementById('ip-map-container');

    // Destroy existing map
    if (ipMap) {
      ipMap.remove();
      ipMap = null;
    }

    if (!lat || !lng) {
      container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-dim);font-family:var(--font-mono);">No coordinates available</div>';
      return;
    }

    ipMap = L.map(container, {
      center: [lat, lng],
      zoom: 6,
      zoomControl: true,
      attributionControl: false,
    });

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18,
    }).addTo(ipMap);

    // Custom pulsing marker using CSS
    const markerIcon = L.divIcon({
      className: '',
      html: `<div style="
        width: 20px; height: 20px; border-radius: 50%;
        background: var(--cyan); box-shadow: 0 0 20px var(--cyan), 0 0 40px rgba(0,240,255,0.3);
        position: relative;
      ">
        <div style="
          position: absolute; inset: -8px; border: 2px solid var(--cyan);
          border-radius: 50%; opacity: 0.4; animation: pulse 2s infinite;
        "></div>
      </div>`,
      iconSize: [20, 20],
      iconAnchor: [10, 10],
    });

    ipMarker = L.marker([lat, lng], { icon: markerIcon }).addTo(ipMap);
    ipMarker.bindPopup(`
      <div style="text-align:center;">
        <div style="font-weight:bold;color:var(--cyan);margin-bottom:4px;">${ip}</div>
        <div>${city || '—'}, ${country || '—'}</div>
        <div style="margin-top:4px;color:var(--text-dim);">${lat.toFixed(4)}, ${lng.toFixed(4)}</div>
      </div>
    `).openPopup();

    // Force map to recalculate size after animation
    setTimeout(() => ipMap.invalidateSize(), 600);
  }

  // ═══════════════ EMAIL PHISHING DETECTOR ═══════════════
  const emlDropzone = $('#eml-dropzone');
  const emlFileInput = $('#eml-file-input');
  const emlLoading = $('#eml-loading');
  const emailFullscreen = $('#email-fullscreen');
  const emailCloseBtn = $('#email-close-btn');
  let emailMap = null;

  // Click to browse
  emlDropzone.addEventListener('click', () => emlFileInput.click());
  emlFileInput.addEventListener('change', (e) => {
    if (e.target.files.length) handleEmlFile(e.target.files[0]);
  });

  // Drag and drop
  emlDropzone.addEventListener('dragover', (e) => { e.preventDefault(); emlDropzone.classList.add('dragover'); });
  emlDropzone.addEventListener('dragleave', () => emlDropzone.classList.remove('dragover'));
  emlDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    emlDropzone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file && (file.name.endsWith('.eml') || file.type === 'message/rfc822')) {
      handleEmlFile(file);
    }
  });

  async function handleEmlFile(file) {
    emlDropzone.hidden = true;
    emlLoading.hidden = false;

    const formData = new FormData();
    formData.append('emlFile', file);

    try {
      const res = await fetch('/api/email/analyze', { method: 'POST', body: formData });
      const data = await res.json();
      if (data.error) {
        alert('Analysis error: ' + data.error);
      } else {
        scansToday++; statScans.textContent = scansToday;
        renderEmailFullscreen(data);
      }
    } catch (err) {
      alert('Email analysis failed. Check server connection.');
    } finally {
      emlDropzone.hidden = false;
      emlLoading.hidden = true;
      emlFileInput.value = '';
    }
  }

  emailCloseBtn.addEventListener('click', () => {
    emailFullscreen.hidden = true;
    document.body.style.overflow = '';
  });

  function authCardClass(status) {
    if (status === 'pass' || status === 'bestguesspass') return 'pass';
    if (status === 'fail') return 'fail';
    if (status === 'softfail' || status === 'neutral') return 'warning';
    return 'none';
  }

  function authIcon(status) {
    if (status === 'pass' || status === 'bestguesspass') return '✅';
    if (status === 'fail') return '❌';
    if (status === 'softfail' || status === 'neutral') return '⚠️';
    return '❔';
  }

  function renderEmailFullscreen(data) {
    emailFullscreen.hidden = false;
    document.body.style.overflow = 'hidden';

    // Subject badge
    $('#email-subject-badge').textContent = data.subject || '(no subject)';

    const color = data.riskColor || '#00f0ff';
    const C = 2 * Math.PI * 42;
    const offset = C - ((data.overallScore || 0) / 100) * C;

    // ── Risk Overview ──
    $('#email-risk-overview').innerHTML = `
      <div class="card-header"><span class="card-icon">🛡️</span><span class="card-title">PHISHING ASSESSMENT</span></div>
      <div class="risk-overview-content">
        <div class="risk-circle-lg">
          <svg viewBox="0 0 100 100"><circle class="track" cx="50" cy="50" r="42"/><circle class="progress" cx="50" cy="50" r="42" stroke="${color}" stroke-dasharray="${C}" stroke-dashoffset="${offset}"/></svg>
          <div class="risk-score-text"><span class="risk-score-number" style="color:${color}">${data.overallScore}</span><span class="risk-score-label">/ 100</span></div>
        </div>
        <div class="risk-overview-info">
          <h3 style="color:${color}">${(data.riskLevel || 'unknown').toUpperCase()} RISK</h3>
          <div class="email-meta-row">
            <div class="email-meta-item"><span class="email-meta-label">From:</span><span class="email-meta-value">${data.from || '—'}</span></div>
            <div class="email-meta-item"><span class="email-meta-label">To:</span><span class="email-meta-value">${data.to || '—'}</span></div>
          </div>
          <div class="email-meta-row">
            <div class="email-meta-item"><span class="email-meta-label">Date:</span><span class="email-meta-value">${data.date ? new Date(data.date).toLocaleString() : '—'}</span></div>
            <div class="email-meta-item"><span class="email-meta-label">Message-ID:</span><span class="email-meta-value">${data.messageId || '—'}</span></div>
          </div>
        </div>
      </div>`;

    // ── SPF / DKIM / DMARC Auth Cards ──
    const authItems = [
      { name: 'SPF', data: data.spf },
      { name: 'DKIM', data: data.dkim },
      { name: 'DMARC', data: data.dmarc },
    ];
    $('#email-auth-grid').innerHTML = authItems.map(a => {
      const cls = authCardClass(a.data.status);
      return `<div class="auth-card ${cls}">
        <div class="auth-card-title">${a.name}</div>
        <div class="auth-status-icon">${authIcon(a.data.status)}</div>
        <div class="auth-status-text">${a.data.status.toUpperCase()}</div>
        <div class="auth-detail">${a.data.detail}</div>
      </div>`;
    }).join('');

    // ── Sender Intelligence + Map ──
    const intel = data.senderIntel || {};
    const geo = intel.geolocation || {};
    const net = intel.networkInfo || {};
    $('#email-sender-info').innerHTML = `
      <div class="ip-loc-item"><span class="ip-loc-label">SENDER IP</span><span class="ip-loc-value">${intel.senderIP || 'Unknown'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">LOCATION</span><span class="ip-loc-value">${geo.city || '—'}, ${geo.country || '—'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">ISP</span><span class="ip-loc-value">${net.isp || '—'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">ORG</span><span class="ip-loc-value">${net.org || '—'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">HOSTING</span><span class="ip-loc-value">${net.hosting ? 'Yes' : 'No'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">PROXY</span><span class="ip-loc-value">${net.proxy ? 'Yes' : 'No'}</span></div>
      <div class="ip-loc-item"><span class="ip-loc-label">DOMAIN</span><span class="ip-loc-value">${intel.domain || '—'}</span></div>`;

    // Init sender map
    initEmailMap(geo.lat, geo.lng, intel.senderIP, geo.city, geo.country);

    // ── Header Analysis ──
    const hdr = data.headerAnalysis || {};
    let hdrHTML = '<div class="card-header"><span class="card-icon">📋</span><span class="card-title">HEADER ANALYSIS</span></div>';
    hdrHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Return-Path</span><span class="ip-kv-value">${hdr.returnPath || '—'}</span></div>`;
    hdrHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Reply-To</span><span class="ip-kv-value">${hdr.replyTo || '(same as From)'}</span></div>`;
    hdrHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Relay Hops</span><span class="ip-kv-value">${hdr.hops || 0}</span></div>`;
    hdrHTML += `<div class="ip-kv-row"><span class="ip-kv-label">From Domain</span><span class="ip-kv-value cyan">${hdr.fromDomain || '—'}</span></div>`;
    if (hdr.findings?.length) {
      hdr.findings.forEach(f => {
        const sevColor = f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'yellow' : 'cyan';
        hdrHTML += `<div class="ip-kv-row"><span class="ip-kv-label">${f.label}</span><span class="ip-kv-value ${sevColor}">${f.detail}</span></div>`;
      });
    }
    $('#email-header-card').innerHTML = hdrHTML;

    // ── Subject Analysis ──
    const subj = data.subjectAnalysis || {};
    let subjHTML = `<div class="card-header"><span class="card-icon">📌</span><span class="card-title">SUBJECT ANALYSIS</span></div>`;
    subjHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Subject</span><span class="ip-kv-value">${subj.subject || '—'}</span></div>`;
    subjHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Score</span><span class="ip-kv-value ${subj.score > 8 ? 'red' : subj.score > 4 ? 'yellow' : 'green'}">+${subj.score || 0}</span></div>`;
    if (subj.findings?.length) {
      subj.findings.forEach(f => {
        const sevColor = f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'yellow' : 'cyan';
        subjHTML += `<div class="ip-kv-row"><span class="ip-kv-label">${f.label}</span><span class="ip-kv-value ${sevColor}">${f.detail}</span></div>`;
      });
    }
    $('#email-subject-card').innerHTML = subjHTML;

    // ── Body Analysis ──
    const body = data.bodyAnalysis || {};
    let bodyHTML = `<div class="card-header"><span class="card-icon">📝</span><span class="card-title">BODY ANALYSIS</span></div>`;
    bodyHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Word Count</span><span class="ip-kv-value">${body.wordCount || 0}</span></div>`;
    bodyHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Score</span><span class="ip-kv-value ${body.score > 10 ? 'red' : body.score > 5 ? 'yellow' : 'green'}">+${body.score || 0}</span></div>`;
    if (body.findings?.length) {
      body.findings.forEach(f => {
        const sevColor = f.severity === 'critical' ? 'magenta' : f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'yellow' : 'cyan';
        bodyHTML += `<div class="ip-kv-row"><span class="ip-kv-label">${f.label}</span><span class="ip-kv-value ${sevColor}">${f.detail}</span></div>`;
        if (f.keywords?.length) {
          bodyHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Keywords</span><span class="ip-kv-value" style="font-size:0.6rem;max-width:70%;text-align:right">${f.keywords.slice(0, 5).join(', ')}${f.keywords.length > 5 ? '...' : ''}</span></div>`;
        }
      });
    }
    $('#email-body-card').innerHTML = bodyHTML;

    // ── Links Analysis ──
    const links = data.linkAnalysis || {};
    let linksHTML = `<div class="card-header"><span class="card-icon">🔗</span><span class="card-title">LINKS ANALYSIS (${links.totalLinks || 0})</span></div>`;
    if (links.links?.length) {
      linksHTML += `<div class="ip-kv-row"><span class="ip-kv-label">High Risk Links</span><span class="ip-kv-value ${links.highRiskCount > 0 ? 'red' : 'green'}">${links.highRiskCount}</span></div>`;
      linksHTML += `<div class="ip-kv-row"><span class="ip-kv-label">Display Mismatches</span><span class="ip-kv-value ${links.displayMismatches > 0 ? 'red' : 'green'}">${links.displayMismatches}</span></div>`;
      linksHTML += '<table class="links-table"><thead><tr><th>URL</th><th>RISK</th><th>DISPLAY</th></tr></thead><tbody>';
      links.links.forEach(l => {
        const badgeBg = l.riskScore >= 50 ? 'rgba(255,68,68,0.15)' : l.riskScore >= 25 ? 'rgba(255,170,0,0.15)' : 'rgba(0,255,136,0.1)';
        const badgeColor = l.color || '#00ff88';
        linksHTML += `<tr>
          <td><span class="link-url" title="${l.url}">${l.url}</span></td>
          <td><span class="link-risk-badge" style="background:${badgeBg};color:${badgeColor}">${l.riskLevel.toUpperCase()} ${l.riskScore}</span></td>
          <td>${l.displayMismatch ? '<span class="ip-kv-value red">⚠ MISMATCH</span>' : '—'}</td>
        </tr>`;
      });
      linksHTML += '</tbody></table>';
    } else {
      linksHTML += '<div class="ip-kv-row"><span class="ip-kv-label">No links found in email</span></div>';
    }
    $('#email-links-card').innerHTML = linksHTML;

    // ── Attachments ──
    const att = data.attachmentAnalysis || {};
    let attHTML = `<div class="card-header"><span class="card-icon">📎</span><span class="card-title">ATTACHMENTS (${att.count || 0})</span></div>`;
    if (att.attachments?.length) {
      att.attachments.forEach(a => {
        const riskColor = a.risk === 'critical' ? 'magenta' : a.risk === 'medium' ? 'yellow' : 'green';
        attHTML += `<div class="ip-kv-row"><span class="ip-kv-label">${a.filename}</span><span class="ip-kv-value ${riskColor}">.${a.extension} — ${a.risk.toUpperCase()}</span></div>`;
      });
      if (att.findings?.length) {
        att.findings.forEach(f => {
          attHTML += `<div class="ip-kv-row"><span class="ip-kv-label">${f.label}</span><span class="ip-kv-value red">${f.detail}</span></div>`;
        });
      }
    } else {
      attHTML += '<div class="ip-kv-row"><span class="ip-kv-label">No attachments</span><span class="status-badge safe">✓ CLEAN</span></div>';
    }
    $('#email-attachments-card').innerHTML = attHTML;

    // ── Recommendations ──
    const recs = data.recommendations || [];
    let recsHTML = '<div class="card-header"><span class="card-icon">💡</span><span class="card-title">RECOMMENDATIONS</span></div>';
    if (recs.length) {
      recsHTML += '<div class="recommendations">' + recs.map(r =>
        `<div class="recommendation"><span class="rec-icon">⚡</span><span>${r}</span></div>`
      ).join('') + '</div>';
    }
    $('#email-recommendations-card').innerHTML = recsHTML;

    // Globe marker for sender
    if (CyberGlobe.isReady && geo.lat && geo.lng) {
      CyberGlobe.addThreatMarker(geo.lat, geo.lng, data.riskLevel, 'email');
    }
  }

  function initEmailMap(lat, lng, ip, city, country) {
    const container = document.getElementById('email-map-container');
    if (emailMap) { emailMap.remove(); emailMap = null; }
    if (!lat || !lng) {
      container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-dim);font-family:var(--font-mono);font-size:0.75rem">Sender location unavailable</div>';
      return;
    }
    emailMap = L.map(container, { center: [lat, lng], zoom: 5, zoomControl: true, attributionControl: false });
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(emailMap);
    const icon = L.divIcon({
      className: '',
      html: `<div style="width:20px;height:20px;border-radius:50%;background:var(--magenta);box-shadow:0 0 20px var(--magenta),0 0 40px rgba(255,0,110,0.3);position:relative;"><div style="position:absolute;inset:-8px;border:2px solid var(--magenta);border-radius:50%;opacity:0.4;animation:pulse 2s infinite;"></div></div>`,
      iconSize: [20, 20], iconAnchor: [10, 10],
    });
    L.marker([lat, lng], { icon }).addTo(emailMap).bindPopup(`<div style="text-align:center;"><div style="font-weight:bold;color:var(--magenta);margin-bottom:4px">Sender: ${ip || '?'}</div><div>${city || '—'}, ${country || '—'}</div></div>`).openPopup();
    setTimeout(() => emailMap.invalidateSize(), 600);
  }

  // ═══════════════ INIT GLOBE ═══════════════
  window.addEventListener('DOMContentLoaded', () => {
    CyberGlobe.init();
  });
})();
