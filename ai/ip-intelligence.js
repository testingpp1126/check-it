/**
 * IP Intelligence Engine — Enhanced
 * Geolocation, threat scoring, VPN/proxy detection, TTL analysis, OS fingerprinting, network classification.
 */

// ── Known threat IP prefixes (simulation) ──
const KNOWN_THREATS = new Set([
    '185.220.101.', '23.129.64.', '171.25.193.',
    '45.33.32.', '198.96.155.',
]);

// ── Known VPN/Proxy providers ──
const VPN_PROVIDERS = [
    'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn', 'mullvad',
    'private internet', 'pia', 'windscribe', 'tunnelbear', 'hotspot shield',
    'hide.me', 'ipvanish', 'purevpn', 'torguard',
];

// ── Known hosting providers ──
const HOSTING_PROVIDERS = [
    'amazon', 'aws', 'google cloud', 'gcp', 'microsoft azure', 'digitalocean',
    'linode', 'vultr', 'ovh', 'hetzner', 'cloudflare', 'akamai', 'fastly',
    'oracle cloud', 'ibm cloud', 'alibaba cloud',
];

// ── TTL → OS mapping ──
const TTL_OS_MAP = [
    { ttl: 64, os: 'Linux / macOS / Android', family: 'unix' },
    { ttl: 128, os: 'Windows', family: 'windows' },
    { ttl: 255, os: 'Cisco IOS / Solaris', family: 'network' },
    { ttl: 60, os: 'AIX', family: 'unix' },
    { ttl: 200, os: 'Windows (older)', family: 'windows' },
];

function isPrivateIP(ip) {
    return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fc|fd)/.test(ip);
}

function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => {
        const n = Number(p);
        return Number.isInteger(n) && n >= 0 && n <= 255;
    });
}

/**
 * Estimate TTL and OS from a simulated initial TTL
 */
function estimateTTLAndOS(ip) {
    // Simulate a TTL value based on IP hash for consistency
    const hash = ip.split('.').reduce((acc, oct) => acc * 31 + parseInt(oct), 0);
    const initialTTLs = [64, 128, 255, 64, 128, 64, 128, 64];
    const baseTTL = initialTTLs[Math.abs(hash) % initialTTLs.length];

    // Simulate hops (distance)
    const hops = 5 + (Math.abs(hash * 7) % 20);
    const observedTTL = Math.max(1, baseTTL - hops);

    // Find closest OS match
    let bestMatch = TTL_OS_MAP[0];
    let bestDist = Infinity;
    for (const entry of TTL_OS_MAP) {
        const dist = Math.abs(baseTTL - entry.ttl);
        if (dist < bestDist) {
            bestDist = dist;
            bestMatch = entry;
        }
    }

    return {
        initialTTL: baseTTL,
        observedTTL,
        hops,
        osGuess: bestMatch.os,
        osFamily: bestMatch.family,
        confidence: bestDist === 0 ? 'high' : bestDist <= 4 ? 'medium' : 'low',
    };
}

/**
 * Classify network type
 */
function classifyNetwork(geoData) {
    const isp = (geoData.isp || '').toLowerCase();
    const org = (geoData.org || '').toLowerCase();
    const as = (geoData.as || '').toLowerCase();

    // Check hosting
    const isHosting = geoData.hosting || HOSTING_PROVIDERS.some(h => isp.includes(h) || org.includes(h));
    if (isHosting) return { type: 'Hosting / Data Center', icon: '🏢', risk: 'elevated' };

    // Check mobile
    if (geoData.mobile) return { type: 'Mobile / Cellular', icon: '📱', risk: 'low' };

    // Check edu
    if (org.includes('university') || org.includes('college') || isp.includes('education')) {
        return { type: 'Education', icon: '🎓', risk: 'low' };
    }

    // Check government
    if (org.includes('government') || org.includes('gov')) {
        return { type: 'Government', icon: '🏛️', risk: 'low' };
    }

    // Default residential/business
    if (isp.includes('comcast') || isp.includes('at&t') || isp.includes('verizon') ||
        isp.includes('spectrum') || isp.includes('cox') || isp.includes('charter') ||
        isp.includes('airtel') || isp.includes('jio') || isp.includes('bsnl')) {
        return { type: 'Residential ISP', icon: '🏠', risk: 'low' };
    }

    return { type: 'Business / Corporate', icon: '🏢', risk: 'low' };
}

/**
 * Detect VPN / Proxy / Tor
 */
function detectVPN(geoData) {
    const isp = (geoData.isp || '').toLowerCase();
    const org = (geoData.org || '').toLowerCase();
    const as = (geoData.as || '').toLowerCase();

    const result = {
        vpnDetected: false,
        proxyDetected: !!geoData.proxy,
        torDetected: false,
        provider: null,
        confidence: 'low',
    };

    // Check known VPN providers
    for (const vpn of VPN_PROVIDERS) {
        if (isp.includes(vpn) || org.includes(vpn) || as.includes(vpn)) {
            result.vpnDetected = true;
            result.provider = vpn.charAt(0).toUpperCase() + vpn.slice(1);
            result.confidence = 'high';
            break;
        }
    }

    // Tor detection
    if (isp.includes('tor') || org.includes('tor exit') || org.includes('torproject')) {
        result.torDetected = true;
        result.confidence = 'high';
    }

    // Hosting + proxy combo often means VPN
    if (geoData.hosting && geoData.proxy) {
        result.vpnDetected = true;
        result.confidence = 'medium';
    }

    return result;
}

/**
 * Calculate comprehensive risk factor
 */
function calculateRiskFactor(threatScore, vpnInfo, networkType, geoData) {
    const factors = [];

    if (vpnInfo.vpnDetected) factors.push({ label: 'VPN Detected', impact: 'medium', score: 15 });
    if (vpnInfo.proxyDetected) factors.push({ label: 'Proxy Detected', impact: 'high', score: 20 });
    if (vpnInfo.torDetected) factors.push({ label: 'Tor Exit Node', impact: 'critical', score: 30 });
    if (networkType.risk === 'elevated') factors.push({ label: 'Data Center IP', impact: 'medium', score: 10 });
    if (geoData.hosting) factors.push({ label: 'Hosting Provider', impact: 'medium', score: 10 });

    const HIGH_RISK_COUNTRIES = new Set(['RU', 'CN', 'KP', 'IR']);
    if (HIGH_RISK_COUNTRIES.has(geoData.countryCode)) {
        factors.push({ label: 'High-Risk Geo', impact: 'medium', score: 10 });
    }

    const riskScore = Math.min(100, factors.reduce((sum, f) => sum + f.score, 0) + threatScore * 0.3);
    let riskRating;
    if (riskScore < 15) riskRating = 'minimal';
    else if (riskScore < 35) riskRating = 'low';
    else if (riskScore < 55) riskRating = 'moderate';
    else if (riskScore < 75) riskRating = 'high';
    else riskRating = 'critical';

    return { riskScore: Math.round(riskScore), riskRating, factors };
}

/**
 * Main lookup function
 */
async function lookupIP(ip) {
    const trimmed = ip.trim();

    if (!isValidIPv4(trimmed)) {
        return { ip: trimmed, error: 'Invalid IPv4 address.', threatScore: 0, threatLevel: 'unknown' };
    }

    if (isPrivateIP(trimmed)) {
        return {
            ip: trimmed,
            isPrivate: true,
            geolocation: null,
            threatScore: 0,
            threatLevel: 'safe',
            summary: 'Private/reserved IP — not routable on the public internet.',
            tags: ['private', 'internal'],
            networkInfo: { isp: 'Private Network', org: 'N/A', as: 'N/A' },
            ttl: { initialTTL: 64, observedTTL: 64, hops: 0, osGuess: 'N/A', osFamily: 'unknown', confidence: 'none' },
            vpn: { vpnDetected: false, proxyDetected: false, torDetected: false, provider: null, confidence: 'none' },
            networkType: { type: 'Private Network', icon: '🔒', risk: 'none' },
            riskFactor: { riskScore: 0, riskRating: 'minimal', factors: [] },
        };
    }

    // Fetch geolocation
    let geo;
    try {
        const resp = await fetch(`http://ip-api.com/json/${trimmed}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`);
        geo = await resp.json();
    } catch {
        geo = { status: 'fail', message: 'API unreachable' };
    }

    if (geo.status === 'fail') {
        return {
            ip: trimmed,
            error: geo.message || 'Geolocation lookup failed.',
            threatScore: 10,
            threatLevel: 'unknown',
            summary: 'Could not determine geolocation.',
        };
    }

    // ── Threat scoring ──
    let threatScore = 0;
    const tags = [];

    if (geo.proxy) { threatScore += 25; tags.push('proxy'); }
    if (geo.hosting) { threatScore += 15; tags.push('hosting-provider'); }
    if (geo.mobile) { tags.push('mobile'); }

    for (const prefix of KNOWN_THREATS) {
        if (trimmed.startsWith(prefix)) {
            threatScore += 35;
            tags.push('known-threat-range');
            break;
        }
    }

    const HIGH_RISK_COUNTRIES = new Set(['RU', 'CN', 'KP', 'IR']);
    if (HIGH_RISK_COUNTRIES.has(geo.countryCode)) {
        threatScore += 10;
        tags.push('high-risk-country');
    }

    const ispLower = (geo.isp || '').toLowerCase();
    if (ispLower.includes('tor') || ispLower.includes('anonymo')) {
        threatScore += 30;
        tags.push('anonymizer');
    }

    threatScore = Math.min(threatScore, 100);

    let threatLevel;
    if (threatScore < 15) threatLevel = 'safe';
    else if (threatScore < 35) threatLevel = 'low';
    else if (threatScore < 60) threatLevel = 'medium';
    else if (threatScore < 80) threatLevel = 'high';
    else threatLevel = 'critical';

    let threatColor;
    if (threatScore < 15) threatColor = '#00ff88';
    else if (threatScore < 35) threatColor = '#a8ff00';
    else if (threatScore < 60) threatColor = '#ffaa00';
    else if (threatScore < 80) threatColor = '#ff4444';
    else threatColor = '#ff006e';

    // ── Enhanced analysis ──
    const ttl = estimateTTLAndOS(trimmed);
    const vpn = detectVPN(geo);
    const networkType = classifyNetwork(geo);
    const riskFactor = calculateRiskFactor(threatScore, vpn, networkType, geo);

    // Add vpn/tor tags
    if (vpn.vpnDetected) tags.push('vpn');
    if (vpn.torDetected) tags.push('tor');

    // ASN parsing
    const asMatch = (geo.as || '').match(/^(AS\d+)\s*(.*)/);
    const asnNumber = asMatch ? asMatch[1] : geo.as || 'N/A';
    const asnName = asMatch ? asMatch[2] : '';

    return {
        ip: trimmed,
        geolocation: {
            country: geo.country,
            countryCode: geo.countryCode,
            region: geo.regionName,
            city: geo.city,
            zip: geo.zip,
            lat: geo.lat,
            lng: geo.lon,
            timezone: geo.timezone,
        },
        networkInfo: {
            isp: geo.isp,
            org: geo.org,
            as: geo.as,
            asnNumber,
            asnName,
            mobile: geo.mobile,
            proxy: geo.proxy,
            hosting: geo.hosting,
        },
        ttl,
        vpn,
        networkType,
        riskFactor,
        threatScore,
        threatLevel,
        threatColor,
        tags,
        summary: `${geo.city}, ${geo.country} — ${riskFactor.riskRating.toUpperCase()} risk (${riskFactor.riskScore}/100)`,
        analyzedAt: new Date().toISOString(),
    };
}

module.exports = { lookupIP };
