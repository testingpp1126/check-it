/**
 * Heuristic-based AI Phishing Detection Engine
 * Scores URLs on 10+ features to detect phishing attempts.
 */

// ── Known suspicious TLDs ──
const SUSPICIOUS_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'club',
    'work', 'info', 'click', 'link', 'surf', 'icu', 'cam', 'monster',
]);

// ── Phishing keywords ──
const PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'account', 'update', 'confirm', 'bank', 'paypal', 'password',
    'credential', 'suspend', 'restrict', 'unlock', 'alert', 'expire',
    'unusual', 'activity', 'billing', 'wallet', 'ssn', 'identity',
];

// ── Homoglyph map (visual look-alikes) ──
const HOMOGLYPHS = {
    'a': ['а', '@', '4'],  // Cyrillic а, at-sign, number 4
    'e': ['е', '3'],       // Cyrillic е
    'o': ['о', '0'],       // Cyrillic о, zero
    'i': ['і', '1', 'l'],
    'l': ['1', 'I', '|'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['9'],
    'b': ['6'],
};

// ── Well-known brands for typosquatting detection ──
const BRANDS = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix',
    'paypal', 'instagram', 'twitter', 'linkedin', 'dropbox', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'yahoo', 'outlook',
];

/**
 * Calculate Shannon entropy of a string
 */
function shannonEntropy(str) {
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    let entropy = 0;
    for (const ch in freq) {
        const p = freq[ch] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/**
 * Levenshtein distance between two strings
 */
function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)
            );
        }
    }
    return dp[m][n];
}

/**
 * Main analysis function
 */
function analyzeUrl(inputUrl) {
    const features = [];
    let totalScore = 0;

    // Normalize
    let url = inputUrl.trim();
    if (!/^https?:\/\//i.test(url)) url = 'http://' + url;

    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return {
            url: inputUrl,
            riskScore: 90,
            riskLevel: 'critical',
            summary: 'Invalid URL structure — highly suspicious.',
            features: [{ name: 'URL Parsing', score: 30, detail: 'URL could not be parsed.' }],
            recommendations: ['Do not visit this URL.'],
        };
    }

    const hostname = parsed.hostname;
    const fullPath = parsed.pathname + parsed.search + parsed.hash;

    // ─── 1. Protocol check ───
    if (parsed.protocol === 'http:') {
        features.push({ name: 'No HTTPS', score: 10, detail: 'Uses insecure HTTP protocol.' });
        totalScore += 10;
    } else {
        features.push({ name: 'HTTPS', score: 0, detail: 'Uses HTTPS (good).' });
    }

    // ─── 2. URL length ───
    const urlLen = url.length;
    if (urlLen > 100) {
        const s = Math.min(Math.floor((urlLen - 100) / 20) * 3, 15);
        features.push({ name: 'Excessive Length', score: s, detail: `URL is ${urlLen} chars long.` });
        totalScore += s;
    }

    // ─── 3. Suspicious keywords ───
    const lower = url.toLowerCase();
    const foundKeywords = PHISHING_KEYWORDS.filter(kw => lower.includes(kw));
    if (foundKeywords.length > 0) {
        const s = Math.min(foundKeywords.length * 5, 20);
        features.push({ name: 'Phishing Keywords', score: s, detail: `Found: ${foundKeywords.join(', ')}` });
        totalScore += s;
    }

    // ─── 4. Special characters in URL ───
    const atCount = (url.match(/@/g) || []).length;
    const dashCount = (hostname.match(/-/g) || []).length;
    const dotCount = (hostname.match(/\./g) || []).length;
    let specialScore = 0;
    if (atCount > 0) specialScore += 15;
    if (dashCount > 3) specialScore += 8;
    if (dotCount > 4) specialScore += 8;
    if (specialScore > 0) {
        features.push({ name: 'Suspicious Characters', score: Math.min(specialScore, 20), detail: `@ symbols: ${atCount}, hyphens: ${dashCount}, dots: ${dotCount}` });
        totalScore += Math.min(specialScore, 20);
    }

    // ─── 5. Entropy analysis ───
    const entropy = shannonEntropy(hostname);
    if (entropy > 4.0) {
        const s = Math.min(Math.floor((entropy - 4.0) * 8), 15);
        features.push({ name: 'High Entropy', score: s, detail: `Domain entropy: ${entropy.toFixed(2)} — possibly random/generated.` });
        totalScore += s;
    }

    // ─── 6. Suspicious TLD ───
    const tld = hostname.split('.').pop().toLowerCase();
    if (SUSPICIOUS_TLDS.has(tld)) {
        features.push({ name: 'Suspicious TLD', score: 10, detail: `.${tld} is commonly abused.` });
        totalScore += 10;
    }

    // ─── 7. Subdomain depth ───
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 2) {
        const s = Math.min(subdomains * 4, 12);
        features.push({ name: 'Deep Subdomains', score: s, detail: `${subdomains} subdomain levels detected.` });
        totalScore += s;
    }

    // ─── 8. IP-based URL ───
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')) {
        features.push({ name: 'IP-based URL', score: 15, detail: 'Uses raw IP address instead of domain.' });
        totalScore += 15;
    }

    // ─── 9. Data URI / encoding ───
    if (lower.includes('data:') || lower.includes('%00') || (url.match(/%[0-9a-f]{2}/gi) || []).length > 5) {
        features.push({ name: 'Encoded Content', score: 12, detail: 'Excessive URL encoding detected.' });
        totalScore += 12;
    }

    // ─── 10. Homoglyph / Typosquatting ───
    let closestBrand = null;
    let closestDist = Infinity;
    const baseDomain = hostname.split('.').slice(-2, -1)[0] || hostname;
    for (const brand of BRANDS) {
        const dist = levenshtein(baseDomain.toLowerCase(), brand);
        if (dist > 0 && dist <= 2 && dist < closestDist) {
            closestDist = dist;
            closestBrand = brand;
        }
    }
    if (closestBrand) {
        features.push({ name: 'Typosquatting', score: 18, detail: `Domain "${baseDomain}" looks like "${closestBrand}" (distance ${closestDist}).` });
        totalScore += 18;
    }

    // ─── 11. Path-based phishing signals ───
    if (fullPath.length > 60) {
        features.push({ name: 'Long Path', score: 5, detail: 'Unusually long URL path.' });
        totalScore += 5;
    }

    // ── Clamp & classify ──
    const riskScore = Math.min(totalScore, 100);
    let riskLevel, color;
    if (riskScore < 20) { riskLevel = 'safe'; color = '#00ff88'; }
    else if (riskScore < 45) { riskLevel = 'low'; color = '#a8ff00'; }
    else if (riskScore < 65) { riskLevel = 'medium'; color = '#ffaa00'; }
    else if (riskScore < 85) { riskLevel = 'high'; color = '#ff4444'; }
    else { riskLevel = 'critical'; color = '#ff006e'; }

    // ── Recommendations ──
    const recommendations = [];
    if (riskLevel === 'safe') recommendations.push('This URL appears safe, but always stay vigilant.');
    if (riskScore >= 20) recommendations.push('Verify the domain is the official site before entering credentials.');
    if (riskScore >= 45) recommendations.push('Do NOT enter personal information on this site.');
    if (riskScore >= 65) recommendations.push('This URL shows strong phishing indicators. Avoid visiting.');
    if (riskScore >= 85) recommendations.push('CRITICAL THREAT — do not interact with this URL under any circumstances.');
    if (closestBrand) recommendations.push(`This may be impersonating ${closestBrand}. Go directly to ${closestBrand}.com instead.`);

    return {
        url: inputUrl,
        riskScore,
        riskLevel,
        color,
        summary: `Risk level: ${riskLevel.toUpperCase()} (${riskScore}/100)`,
        features: features.sort((a, b) => b.score - a.score),
        recommendations,
        analyzedAt: new Date().toISOString(),
    };
}

module.exports = { analyzeUrl };
