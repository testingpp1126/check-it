/**
 * Email Phishing Analyzer — AI-powered .eml File Analysis
 * Parses email headers, body, and authentication results to detect phishing.
 * Checks: SPF, DKIM, DMARC, headers, subject, body, links, sender intelligence.
 */

const { simpleParser } = require('mailparser');
const { analyzeUrl } = require('./phishing-model');

// ── Phishing subject keywords ──
const URGENCY_KEYWORDS = [
    'urgent', 'immediate', 'action required', 'verify', 'suspended',
    'locked', 'unusual activity', 'confirm', 'expire', 'warning',
    'alert', 'important', 'security', 'update required', 'final notice',
    'last chance', 'respond now', 'limited time', 'act now', 'deadline',
];

const PHISHING_BODY_KEYWORDS = [
    'click here', 'verify your account', 'confirm your identity',
    'update your payment', 'suspicious activity', 'your account has been',
    'enter your password', 'social security', 'credit card',
    'wire transfer', 'gift card', 'bitcoin', 'cryptocurrency',
    'dear customer', 'dear user', 'dear valued', 'dear account holder',
    'log in immediately', 'failure to comply', 'will be terminated',
    'within 24 hours', 'within 48 hours', 'will be suspended',
    'unauthorized access', 'reset your password', 'unusual sign-in',
];

// ── Known freemail providers ──
const FREEMAIL = new Set([
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'protonmail.com', 'mail.com', 'yandex.com', 'gmx.com', 'icloud.com',
    'zoho.com', 'tutanota.com', 'fastmail.com',
]);

/**
 * Parse SPF result from headers
 */
function parseSPF(headers) {
    const result = { status: 'none', detail: 'No SPF record found in headers', score: 0 };

    // Check Received-SPF header
    const spfHeader = headers.get('received-spf');
    if (spfHeader) {
        const val = (typeof spfHeader === 'string' ? spfHeader : spfHeader.text || String(spfHeader)).toLowerCase();
        if (val.startsWith('pass')) {
            result.status = 'pass';
            result.detail = 'SPF authentication passed — sender IP is authorized.';
            result.score = 0;
        } else if (val.startsWith('fail')) {
            result.status = 'fail';
            result.detail = 'SPF FAILED — sender IP is NOT authorized to send for this domain.';
            result.score = 25;
        } else if (val.startsWith('softfail')) {
            result.status = 'softfail';
            result.detail = 'SPF soft-fail — sender IP is not listed but not explicitly denied.';
            result.score = 15;
        } else if (val.startsWith('neutral')) {
            result.status = 'neutral';
            result.detail = 'SPF neutral — domain does not assert whether IP is authorized.';
            result.score = 8;
        } else if (val.startsWith('temperror') || val.startsWith('permerror')) {
            result.status = 'error';
            result.detail = 'SPF check encountered an error.';
            result.score = 10;
        }
        result.raw = val.substring(0, 200);
    }

    // Also check Authentication-Results
    const authResults = headers.get('authentication-results');
    if (authResults && result.status === 'none') {
        const val = (typeof authResults === 'string' ? authResults : authResults.text || String(authResults)).toLowerCase();
        const spfMatch = val.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
        if (spfMatch) {
            result.status = spfMatch[1];
            result.detail = `SPF ${spfMatch[1]} (from Authentication-Results header)`;
            result.score = spfMatch[1] === 'pass' ? 0 : spfMatch[1] === 'fail' ? 25 : 10;
        }
    }

    return result;
}

/**
 * Parse DKIM result from headers
 */
function parseDKIM(headers) {
    const result = { status: 'none', detail: 'No DKIM signature found', score: 0, domain: null };

    // Check DKIM-Signature header existence
    const dkimSig = headers.get('dkim-signature');
    if (dkimSig) {
        const val = typeof dkimSig === 'string' ? dkimSig : dkimSig.text || String(dkimSig);
        const domainMatch = val.match(/d=([^;\s]+)/i);
        if (domainMatch) result.domain = domainMatch[1];
    }

    // Check Authentication-Results for DKIM result
    const authResults = headers.get('authentication-results');
    if (authResults) {
        const val = (typeof authResults === 'string' ? authResults : authResults.text || String(authResults)).toLowerCase();
        const dkimMatch = val.match(/dkim=(pass|fail|neutral|none|temperror|permerror)/i);
        if (dkimMatch) {
            result.status = dkimMatch[1];
            if (dkimMatch[1] === 'pass') {
                result.detail = `DKIM signature verified${result.domain ? ` for ${result.domain}` : ''}.`;
                result.score = 0;
            } else if (dkimMatch[1] === 'fail') {
                result.detail = 'DKIM signature FAILED — email may have been tampered with.';
                result.score = 20;
            } else {
                result.detail = `DKIM ${dkimMatch[1]}`;
                result.score = 10;
            }
        }
    } else if (dkimSig) {
        result.status = 'present';
        result.detail = `DKIM signature present${result.domain ? ` (domain: ${result.domain})` : ''}, but verification result not in headers.`;
        result.score = 5;
    }

    if (!dkimSig && result.status === 'none') {
        result.detail = 'No DKIM signature — email authenticity cannot be verified.';
        result.score = 15;
    }

    return result;
}

/**
 * Parse DMARC result from headers
 */
function parseDMARC(headers) {
    const result = { status: 'none', detail: 'No DMARC policy found in authentication results', score: 0 };

    const authResults = headers.get('authentication-results');
    if (authResults) {
        const val = (typeof authResults === 'string' ? authResults : authResults.text || String(authResults)).toLowerCase();
        const dmarcMatch = val.match(/dmarc=(pass|fail|bestguesspass|none|temperror|permerror)/i);
        if (dmarcMatch) {
            result.status = dmarcMatch[1];
            if (dmarcMatch[1] === 'pass' || dmarcMatch[1] === 'bestguesspass') {
                result.detail = 'DMARC alignment passed — SPF/DKIM aligned with sender domain.';
                result.score = 0;
            } else if (dmarcMatch[1] === 'fail') {
                result.detail = 'DMARC FAILED — SPF/DKIM do NOT align with sender domain. High phishing risk.';
                result.score = 25;
            } else {
                result.detail = `DMARC ${dmarcMatch[1]}`;
                result.score = 10;
            }
        }
    }

    return result;
}

/**
 * Analyze email headers for anomalies
 */
function analyzeHeaders(parsed, headers) {
    const findings = [];
    let score = 0;

    // From vs Return-Path mismatch
    const from = parsed.from?.value?.[0]?.address || '';
    const returnPath = headers.get('return-path');
    const returnPathAddr = returnPath ? (typeof returnPath === 'string' ? returnPath : String(returnPath)).replace(/[<>]/g, '').trim() : '';

    if (from && returnPathAddr && from.toLowerCase() !== returnPathAddr.toLowerCase()) {
        const fromDomain = from.split('@')[1] || '';
        const rpDomain = returnPathAddr.split('@')[1] || '';
        if (fromDomain !== rpDomain) {
            findings.push({ label: 'From ≠ Return-Path', detail: `From: ${from} vs Return-Path: ${returnPathAddr}`, severity: 'high' });
            score += 15;
        }
    }

    // Reply-To mismatch
    const replyTo = parsed.replyTo?.value?.[0]?.address || '';
    if (replyTo && from && replyTo.toLowerCase() !== from.toLowerCase()) {
        findings.push({ label: 'Reply-To mismatch', detail: `From: ${from} but Reply-To: ${replyTo}`, severity: 'medium' });
        score += 10;
    }

    // Analyze Received chain
    const received = headers.get('received');
    const receivedArr = Array.isArray(received) ? received : received ? [received] : [];
    const hops = receivedArr.length;
    if (hops > 8) {
        findings.push({ label: 'Excessive relay hops', detail: `${hops} hops detected — possible obfuscation.`, severity: 'medium' });
        score += 8;
    }

    // Extract sender IPs from Received headers
    const senderIPs = [];
    receivedArr.forEach(r => {
        const rStr = typeof r === 'string' ? r : r.text || String(r);
        const ipMatches = rStr.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/g);
        if (ipMatches) ipMatches.forEach(ip => senderIPs.push(ip.replace(/[\[\]]/g, '')));
    });

    // Check Message-ID domain
    const messageId = headers.get('message-id');
    if (messageId) {
        const midStr = typeof messageId === 'string' ? messageId : String(messageId);
        const midDomain = midStr.match(/@([^>]+)/);
        const fromDomain = from.split('@')[1] || '';
        if (midDomain && fromDomain && !midDomain[1].includes(fromDomain)) {
            findings.push({ label: 'Message-ID domain mismatch', detail: `Message-ID domain: ${midDomain[1]}, From domain: ${fromDomain}`, severity: 'low' });
            score += 5;
        }
    }

    // X-Mailer check
    const xMailer = headers.get('x-mailer');
    if (xMailer) {
        const val = typeof xMailer === 'string' ? xMailer : String(xMailer);
        findings.push({ label: 'X-Mailer', detail: val, severity: 'info' });
    }

    // Freemail sender pretending to be corporate
    const fromDomain = from.split('@')[1] || '';
    if (FREEMAIL.has(fromDomain.toLowerCase())) {
        findings.push({ label: 'Freemail sender', detail: `Sent from freemail provider: ${fromDomain}`, severity: 'low' });
        score += 3;
    }

    return { findings, score, hops, senderIPs, fromAddress: from, fromDomain, returnPath: returnPathAddr, replyTo };
}

/**
 * Analyze subject line
 */
function analyzeSubject(subject) {
    const findings = [];
    let score = 0;

    if (!subject) {
        findings.push({ label: 'Empty subject', detail: 'No subject line — suspicious.', severity: 'medium' });
        return { findings, score: 8, subject: '(empty)' };
    }

    const lower = subject.toLowerCase();

    // Urgency keywords
    const foundKeywords = URGENCY_KEYWORDS.filter(kw => lower.includes(kw));
    if (foundKeywords.length > 0) {
        const s = Math.min(foundKeywords.length * 4, 15);
        findings.push({ label: 'Urgency keywords', detail: `Found: ${foundKeywords.join(', ')}`, severity: foundKeywords.length > 2 ? 'high' : 'medium' });
        score += s;
    }

    // Re:/Fw: trick (multiple prefixes)
    const reFwCount = (subject.match(/^(re:|fw:|fwd:)/gi) || []).length;
    if (reFwCount > 1) {
        findings.push({ label: 'Fake reply chain', detail: `${reFwCount} RE:/FW: prefixes — may fake an ongoing conversation.`, severity: 'medium' });
        score += 8;
    }

    // Excessive caps
    const capsRatio = (subject.match(/[A-Z]/g) || []).length / subject.length;
    if (capsRatio > 0.6 && subject.length > 10) {
        findings.push({ label: 'Excessive capitalization', detail: `${Math.round(capsRatio * 100)}% uppercase — pressure tactic.`, severity: 'low' });
        score += 5;
    }

    // Special characters / emojis abuse
    const specialChars = (subject.match(/[⚠️🔒🚨❗‼️⚡🔴❌✅💰🎁]/g) || []).length;
    if (specialChars > 1) {
        findings.push({ label: 'Emoji/symbol abuse', detail: `${specialChars} attention-grabbing symbols in subject.`, severity: 'low' });
        score += 4;
    }

    return { findings, score, subject };
}

/**
 * Analyze email body content
 */
function analyzeBody(text, html) {
    const findings = [];
    let score = 0;
    const body = (text || '').toLowerCase();

    // Phishing keywords
    const foundKeywords = PHISHING_BODY_KEYWORDS.filter(kw => body.includes(kw));
    if (foundKeywords.length > 0) {
        const s = Math.min(foundKeywords.length * 3, 20);
        findings.push({ label: 'Phishing language', detail: `${foundKeywords.length} suspicious phrases detected.`, severity: foundKeywords.length > 3 ? 'high' : 'medium', keywords: foundKeywords });
        score += s;
    }

    // Check for credential harvesting forms
    if (html) {
        const htmlLower = html.toLowerCase();
        const hasForms = (htmlLower.match(/<form/g) || []).length;
        const hasPasswordField = htmlLower.includes('type="password"') || htmlLower.includes("type='password'");
        if (hasForms > 0) {
            findings.push({ label: 'Embedded form', detail: `${hasForms} form(s) found in email body.`, severity: 'high' });
            score += 12;
        }
        if (hasPasswordField) {
            findings.push({ label: 'Password field', detail: 'Email contains an embedded password input — credential harvesting.', severity: 'critical' });
            score += 20;
        }

        // Hidden text (display:none, font-size:0, color matching background)
        if (htmlLower.includes('display:none') || htmlLower.includes('display: none') ||
            htmlLower.includes('font-size:0') || htmlLower.includes('font-size: 0') ||
            htmlLower.includes('visibility:hidden')) {
            findings.push({ label: 'Hidden content', detail: 'Email contains hidden text — possible evasion technique.', severity: 'medium' });
            score += 8;
        }
    }

    // Urgency / threatening language
    const urgentPhrases = ['will be terminated', 'will be suspended', 'will be locked',
        'within 24 hours', 'within 48 hours', 'failure to', 'legal action',
        'law enforcement', 'account closed', 'permanent', 'immediately'];
    const foundUrgent = urgentPhrases.filter(p => body.includes(p));
    if (foundUrgent.length > 0) {
        findings.push({ label: 'Threatening language', detail: `${foundUrgent.length} threat/urgency phrases.`, severity: 'high', keywords: foundUrgent });
        score += Math.min(foundUrgent.length * 4, 15);
    }

    return { findings, score, wordCount: (text || '').split(/\s+/).filter(Boolean).length };
}

/**
 * Extract and analyze all links in email
 */
function analyzeLinks(text, html) {
    const links = [];
    const seen = new Set();

    // Extract from HTML (href and display text)
    if (html) {
        const hrefRegex = /<a[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
        let match;
        while ((match = hrefRegex.exec(html)) !== null) {
            const href = match[1].trim();
            const displayText = match[2].replace(/<[^>]*>/g, '').trim();
            if (!seen.has(href) && href.startsWith('http')) {
                seen.add(href);
                const urlAnalysis = analyzeUrl(href);
                const displayMismatch = displayText.startsWith('http') && !displayText.includes(new URL(href).hostname);
                links.push({
                    url: href,
                    displayText: displayText || null,
                    displayMismatch,
                    riskScore: urlAnalysis.riskScore,
                    riskLevel: urlAnalysis.riskLevel,
                    color: urlAnalysis.color,
                    features: urlAnalysis.features?.slice(0, 3) || [],
                });
            }
        }
    }

    // Extract from plain text
    if (text) {
        const urlRegex = /https?:\/\/[^\s<>"']+/g;
        let match;
        while ((match = urlRegex.exec(text)) !== null) {
            const url = match[0].replace(/[.,;)}\]]+$/, '');
            if (!seen.has(url)) {
                seen.add(url);
                const urlAnalysis = analyzeUrl(url);
                links.push({
                    url,
                    displayText: null,
                    displayMismatch: false,
                    riskScore: urlAnalysis.riskScore,
                    riskLevel: urlAnalysis.riskLevel,
                    color: urlAnalysis.color,
                    features: urlAnalysis.features?.slice(0, 3) || [],
                });
            }
        }
    }

    // Overall link score
    let score = 0;
    const highRiskLinks = links.filter(l => l.riskScore >= 50);
    if (highRiskLinks.length > 0) {
        score += Math.min(highRiskLinks.length * 8, 20);
    }
    const displayMismatches = links.filter(l => l.displayMismatch);
    if (displayMismatches.length > 0) {
        score += displayMismatches.length * 10;
    }

    return { links, score, totalLinks: links.length, highRiskCount: highRiskLinks.length, displayMismatches: displayMismatches.length };
}

/**
 * Get sender IP intelligence (geolocation via ip-api.com)
 */
async function getSenderIntelligence(senderIPs, fromDomain) {
    const result = {
        senderIP: null,
        geolocation: null,
        networkInfo: null,
        domain: fromDomain,
    };

    // Try to find the originating IP (usually last in chain, first non-private)
    const publicIPs = senderIPs.filter(ip => !(/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip)));
    const targetIP = publicIPs[publicIPs.length - 1] || publicIPs[0];

    if (!targetIP) return result;
    result.senderIP = targetIP;

    try {
        const resp = await fetch(`http://ip-api.com/json/${targetIP}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting`);
        const geo = await resp.json();
        if (geo.status === 'success') {
            result.geolocation = {
                country: geo.country,
                countryCode: geo.countryCode,
                region: geo.regionName,
                city: geo.city,
                lat: geo.lat,
                lng: geo.lon,
                timezone: geo.timezone,
            };
            result.networkInfo = {
                isp: geo.isp,
                org: geo.org,
                as: geo.as,
                proxy: geo.proxy,
                hosting: geo.hosting,
            };
        }
    } catch {
        // Geolocation unavailable
    }

    return result;
}

/**
 * Analyze attachments
 */
function analyzeAttachments(attachments) {
    const findings = [];
    let score = 0;
    const dangerousExts = new Set(['exe', 'bat', 'cmd', 'scr', 'pif', 'js', 'vbs', 'wsf', 'ps1', 'lnk', 'hta', 'msi']);
    const suspiciousExts = new Set(['zip', 'rar', '7z', 'iso', 'img', 'docm', 'xlsm', 'pptm']);

    const parsed = (attachments || []).map(att => {
        const name = att.filename || 'unknown';
        const ext = name.split('.').pop().toLowerCase();
        const size = att.size || 0;
        let risk = 'safe';

        if (dangerousExts.has(ext)) {
            risk = 'critical';
            score += 20;
            findings.push({ label: `Dangerous attachment: ${name}`, detail: `.${ext} files can execute malware.`, severity: 'critical' });
        } else if (suspiciousExts.has(ext)) {
            risk = 'medium';
            score += 8;
            findings.push({ label: `Suspicious attachment: ${name}`, detail: `.${ext} files may contain hidden executables.`, severity: 'medium' });
        }

        // Double extension trick (e.g., invoice.pdf.exe)
        const parts = name.split('.');
        if (parts.length > 2) {
            const secondLast = parts[parts.length - 2].toLowerCase();
            if (['pdf', 'doc', 'jpg', 'png', 'xlsx'].includes(secondLast) && dangerousExts.has(ext)) {
                risk = 'critical';
                score += 15;
                findings.push({ label: 'Double extension trick', detail: `${name} — disguised as .${secondLast} but is .${ext}`, severity: 'critical' });
            }
        }

        return { filename: name, extension: ext, size, contentType: att.contentType, risk };
    });

    return { attachments: parsed, findings, score, count: parsed.length };
}

/**
 * Main analysis function — parses .eml buffer and returns full report
 */
async function analyzeEmail(emlBuffer) {
    // Parse the .eml file
    const parsed = await simpleParser(emlBuffer);
    const headers = parsed.headers;

    // Run all analysis modules
    const spf = parseSPF(headers);
    const dkim = parseDKIM(headers);
    const dmarc = parseDMARC(headers);
    const headerAnalysis = analyzeHeaders(parsed, headers);
    const subjectAnalysis = analyzeSubject(parsed.subject);
    const bodyAnalysis = analyzeBody(parsed.text, parsed.html);
    const linkAnalysis = analyzeLinks(parsed.text, parsed.html);
    const attachmentAnalysis = analyzeAttachments(parsed.attachments);
    const senderIntel = await getSenderIntelligence(headerAnalysis.senderIPs, headerAnalysis.fromDomain);

    // ── Overall score ──
    const rawScore = spf.score + dkim.score + dmarc.score +
        headerAnalysis.score + subjectAnalysis.score +
        bodyAnalysis.score + linkAnalysis.score + attachmentAnalysis.score;
    const overallScore = Math.min(100, rawScore);

    let riskLevel, riskColor;
    if (overallScore < 15) { riskLevel = 'safe'; riskColor = '#00ff88'; }
    else if (overallScore < 35) { riskLevel = 'low'; riskColor = '#a8ff00'; }
    else if (overallScore < 55) { riskLevel = 'medium'; riskColor = '#ffaa00'; }
    else if (overallScore < 75) { riskLevel = 'high'; riskColor = '#ff4444'; }
    else { riskLevel = 'critical'; riskColor = '#ff006e'; }

    // ── Recommendations ──
    const recommendations = [];
    if (spf.status === 'fail') recommendations.push('SPF failure indicates the sender is not authorized. Do not trust this email.');
    if (dkim.status === 'fail') recommendations.push('DKIM failure means the email content may have been altered in transit.');
    if (dmarc.status === 'fail') recommendations.push('DMARC failure — the sender domain cannot be authenticated. Likely spoofed.');
    if (linkAnalysis.highRiskCount > 0) recommendations.push(`${linkAnalysis.highRiskCount} high-risk link(s) detected. Do NOT click any links.`);
    if (linkAnalysis.displayMismatches > 0) recommendations.push('Link display text does not match actual URL — a classic phishing technique.');
    if (headerAnalysis.findings.some(f => f.label === 'From ≠ Return-Path')) recommendations.push('Sender address does not match return path — possible spoofing.');
    if (bodyAnalysis.score > 10) recommendations.push('Email body contains multiple phishing indicators. Do not provide any personal information.');
    if (attachmentAnalysis.score > 0) recommendations.push('Potentially dangerous attachments detected. Do NOT open them.');
    if (overallScore < 20) recommendations.push('This email appears legitimate, but always verify through official channels.');

    return {
        // Metadata
        subject: parsed.subject || '(no subject)',
        from: parsed.from?.text || 'Unknown',
        fromAddress: headerAnalysis.fromAddress,
        to: parsed.to?.text || 'Unknown',
        date: parsed.date?.toISOString() || null,
        messageId: parsed.messageId || null,

        // Scores
        overallScore,
        riskLevel,
        riskColor,

        // Auth results
        spf,
        dkim,
        dmarc,

        // Analysis
        headerAnalysis: {
            findings: headerAnalysis.findings,
            score: headerAnalysis.score,
            hops: headerAnalysis.hops,
            returnPath: headerAnalysis.returnPath,
            replyTo: headerAnalysis.replyTo,
            fromDomain: headerAnalysis.fromDomain,
        },
        subjectAnalysis,
        bodyAnalysis,
        linkAnalysis,
        attachmentAnalysis,

        // Intelligence
        senderIntel,

        // Recommendations
        recommendations,
        analyzedAt: new Date().toISOString(),
    };
}

module.exports = { analyzeEmail };
