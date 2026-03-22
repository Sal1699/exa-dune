#!/usr/bin/env node
/**
 * websocket_audit.js — WebSocket Security Auditor
 * Uso: node websocket_audit.js <target> [--port 8080] [--path /ws] [--mode probe|fuzz|auth]
 * Richiede: npm install ws (o usa require('ws') se disponibile)
 */

'use strict';

const net = require('net');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

// Parse argomenti CLI minimale
function parseArgs(argv) {
    const args = { target: null, port: 8080, path: null, mode: 'probe', tls: false };
    const positionals = [];
    for (let i = 2; i < argv.length; i++) {
        switch (argv[i]) {
            case '--port':    args.port = parseInt(argv[++i]); break;
            case '--path':    args.path = argv[++i]; break;
            case '--mode':    args.mode = argv[++i]; break;
            case '--tls':     args.tls = true; break;
            case '--help':
                console.log('Uso: node websocket_audit.js <target> [--port 8080] [--path /ws] [--mode probe|fuzz|auth] [--tls]');
                process.exit(0);
            default:
                if (!argv[i].startsWith('--')) positionals.push(argv[i]);
        }
    }
    if (positionals.length > 0) args.target = positionals[0];
    return args;
}

const COMMON_WS_PATHS = [
    '/ws', '/websocket', '/live', '/stream', '/api/ws', '/rtsp',
    '/camera', '/socket', '/realtime', '/push', '/events',
    '/api/v1/ws', '/control', '/notify', '/feed',
];

// Genera WebSocket handshake key
function wsKey() {
    return crypto.randomBytes(16).toString('base64');
}

// WebSocket handshake raw via net
function wsConnect(target, port, path, useTLS, timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
        const key = wsKey();
        const handshake = [
            `GET ${path} HTTP/1.1`,
            `Host: ${target}:${port}`,
            'Upgrade: websocket',
            'Connection: Upgrade',
            `Sec-WebSocket-Key: ${key}`,
            'Sec-WebSocket-Version: 13',
            'User-Agent: exa-dune-ws-audit/1.0',
            '',
            '',
        ].join('\r\n');

        let sock;
        if (useTLS) {
            const tls = require('tls');
            sock = tls.connect({ host: target, port, rejectUnauthorized: false });
        } else {
            sock = net.connect({ host: target, port });
        }

        const timer = setTimeout(() => {
            sock.destroy();
            reject(new Error('timeout'));
        }, timeoutMs);

        let buffer = Buffer.alloc(0);
        let headersDone = false;
        let messages = [];
        let statusCode = null;
        let headers = {};

        sock.on('connect', () => {
            sock.write(handshake);
        });

        sock.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);

            if (!headersDone) {
                const sep = buffer.indexOf('\r\n\r\n');
                if (sep !== -1) {
                    const headerStr = buffer.slice(0, sep).toString();
                    buffer = buffer.slice(sep + 4);
                    headersDone = true;

                    // Parse status
                    const firstLine = headerStr.split('\r\n')[0];
                    const m = firstLine.match(/HTTP\/1\.1 (\d+)/);
                    if (m) statusCode = parseInt(m[1]);

                    // Parse headers
                    headerStr.split('\r\n').slice(1).forEach(line => {
                        const [k, ...rest] = line.split(':');
                        if (k) headers[k.trim().toLowerCase()] = rest.join(':').trim();
                    });

                    if (statusCode === 101) {
                        // WebSocket upgraded — ora leggi frame
                        clearTimeout(timer);
                        // Aspetta messaggi per 3s poi risolve
                        setTimeout(() => {
                            sock.destroy();
                            resolve({ status: 101, headers, messages });
                        }, 3000);
                    } else {
                        clearTimeout(timer);
                        sock.destroy();
                        resolve({ status: statusCode, headers, messages });
                    }
                }
            } else if (headersDone) {
                // Decode WebSocket frames (minimal)
                while (buffer.length >= 2) {
                    const b0 = buffer[0];
                    const b1 = buffer[1];
                    const opcode = b0 & 0x0F;
                    const masked = (b1 & 0x80) !== 0;
                    let payloadLen = b1 & 0x7F;
                    let offset = 2;

                    if (payloadLen === 126) {
                        if (buffer.length < 4) break;
                        payloadLen = buffer.readUInt16BE(2);
                        offset = 4;
                    } else if (payloadLen === 127) {
                        if (buffer.length < 10) break;
                        payloadLen = Number(buffer.readBigUInt64BE(2));
                        offset = 10;
                    }

                    const maskLen = masked ? 4 : 0;
                    const totalLen = offset + maskLen + payloadLen;
                    if (buffer.length < totalLen) break;

                    let payload;
                    if (masked) {
                        const mask = buffer.slice(offset, offset + 4);
                        const data = buffer.slice(offset + 4, totalLen);
                        payload = Buffer.alloc(payloadLen);
                        for (let i = 0; i < payloadLen; i++) payload[i] = data[i] ^ mask[i % 4];
                    } else {
                        payload = buffer.slice(offset, totalLen);
                    }

                    if (opcode === 1 || opcode === 2) {  // text or binary
                        const msg = payload.toString('utf8', 0, Math.min(payloadLen, 500));
                        messages.push(msg);
                    }
                    buffer = buffer.slice(totalLen);
                }
            }
        });

        sock.on('error', (err) => {
            clearTimeout(timer);
            reject(err);
        });

        sock.on('close', () => {
            clearTimeout(timer);
            resolve({ status: statusCode, headers, messages });
        });
    });
}

// Invia un frame WebSocket text (client → server, no mask per semplicità con server lax)
function buildWsFrame(message) {
    const payload = Buffer.from(message, 'utf8');
    const len = payload.length;
    let header;
    if (len < 126) {
        header = Buffer.from([0x81, len]); // FIN + text opcode, no mask
    } else if (len < 65536) {
        header = Buffer.from([0x81, 126, len >> 8, len & 0xFF]);
    } else {
        header = Buffer.from([0x81, 127, 0, 0, 0, 0, (len >> 24) & 0xFF, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF]);
    }
    return Buffer.concat([header, payload]);
}

function tryWs(target, port, path, useTLS) {
    return wsConnect(target, port, path, useTLS).catch(e => ({ status: null, error: e.message }));
}

// Prova prima il modulo 'ws' se disponibile
function tryWsModule() {
    try {
        return require('ws');
    } catch (e) {
        return null;
    }
}

async function modeProbe(target, port, paths, useTLS) {
    console.log(`[*] WebSocket Probe — ${useTLS ? 'wss' : 'ws'}://${target}:${port}`);
    const ws = tryWsModule();
    const proto = useTLS ? 'wss' : 'ws';

    const pathsToTest = paths || COMMON_WS_PATHS;
    const found = [];

    for (const p of pathsToTest) {
        let result;
        if (ws) {
            result = await new Promise(resolve => {
                const url = `${proto}://${target}:${port}${p}`;
                const client = new ws(url, { rejectUnauthorized: false, timeout: 5000 });
                const msgs = [];
                const timer = setTimeout(() => {
                    client.terminate();
                    resolve({ status: 101, messages: msgs });
                }, 4000);
                client.on('open', () => {
                    resolve({ status: 101, messages: [] });
                    clearTimeout(timer);
                    // Aspetta messaggi
                    setTimeout(() => {
                        resolve({ status: 101, messages: msgs });
                        client.terminate();
                    }, 3000);
                });
                client.on('message', (d) => msgs.push(d.toString().slice(0, 200)));
                client.on('error', (e) => { clearTimeout(timer); resolve({ status: null, error: e.message }); });
                client.on('unexpected-response', (req, res) => {
                    clearTimeout(timer);
                    resolve({ status: res.statusCode, messages: [] });
                });
            });
        } else {
            result = await tryWs(target, port, p, useTLS);
        }

        if (result.status === 101) {
            console.log(`[FOUND:HIGH]  WebSocket aperto: ${p}`);
            found.push({ path: p, messages: result.messages || [] });
            if (result.messages && result.messages.length > 0) {
                console.log(`    Messaggi iniziali (${result.messages.length}):`);
                result.messages.slice(0, 3).forEach(m => {
                    console.log(`    → ${m.slice(0, 150)}`);
                    // Cerca dati sensibili
                    if (/password|token|secret|auth|key|credential/i.test(m)) {
                        console.log(`[FOUND:CRITICAL] Dati sensibili nel messaggio WebSocket: ${p}`);
                    }
                });
            }
        } else if (result.status === 403 || result.status === 401) {
            console.log(`[FOUND:MEDIUM] WebSocket protetto: ${p} (HTTP ${result.status})`);
        } else if (result.status) {
            console.log(`[ ]            ${p} → HTTP ${result.status}`);
        }
    }
    return found;
}

async function modeAuth(target, port, paths, useTLS) {
    console.log(`[*] WebSocket Auth Test — connessione senza token`);
    // Testa se un WebSocket aperto senza token invia dati protetti
    const found = await modeProbe(target, port, paths, useTLS);
    for (const f of found) {
        if (f.messages && f.messages.length > 0) {
            console.log(`[FOUND:HIGH]  WebSocket ${f.path} invia dati senza autenticazione`);
        }
    }
}

async function modeFuzz(target, port, paths, useTLS) {
    console.log(`[*] WebSocket Fuzz — messaggi JSON malformati`);
    const ws = tryWsModule();
    if (!ws) {
        console.log('[!] modulo ws non disponibile — fuzz limitato');
        return;
    }
    const proto = useTLS ? 'wss' : 'ws';
    const fuzzPayloads = [
        '{"action": null}',
        '{"a":"' + 'A'.repeat(8192) + '"}',
        '<script>alert(1)</script>',
        '{"__proto__": {"admin": true}}',
        '{"action": "' + '\x00'.repeat(10) + '"}',
        'invalid json!!!',
        '{}',
        '[]',
        'null',
        '{"action": "../../../etc/passwd"}',
    ];

    const pathsToTest = paths || COMMON_WS_PATHS.slice(0, 5);
    for (const p of pathsToTest) {
        const url = `${proto}://${target}:${port}${p}`;
        const client = new ws(url, { rejectUnauthorized: false, timeout: 5000 });
        const responses = [];

        await new Promise(resolve => {
            const timer = setTimeout(() => { client.terminate(); resolve(); }, 8000);
            client.on('open', () => {
                console.log(`    WebSocket aperto: ${p} — invio fuzz payloads`);
                let i = 0;
                const sendNext = () => {
                    if (i >= fuzzPayloads.length) {
                        clearTimeout(timer);
                        client.terminate();
                        return resolve();
                    }
                    client.send(fuzzPayloads[i++], sendNext);
                };
                sendNext();
            });
            client.on('message', (d) => {
                const msg = d.toString().slice(0, 200);
                responses.push(msg);
                if (/error|exception|stack|traceback|undefined|null.*null/i.test(msg)) {
                    console.log(`[FOUND:MEDIUM] WebSocket fuzz errore rilevato: ${msg.slice(0, 100)}`);
                }
            });
            client.on('error', () => { clearTimeout(timer); resolve(); });
        });

        if (responses.length > 0) {
            console.log(`[FOUND:INFO]  ${p} — ${responses.length} risposte a fuzz`);
        }
    }
}

async function main() {
    const args = parseArgs(process.argv);

    if (!args.target) {
        console.error('Errore: target mancante');
        console.error('Uso: node websocket_audit.js <target> [--port 8080] [--path /ws] [--mode probe|fuzz|auth]');
        process.exit(1);
    }

    const pathsToTest = args.path ? [args.path] : null;

    console.log(`[*] WebSocket Audit — ${args.target}:${args.port} | Mode: ${args.mode}`);

    if (args.mode === 'probe') {
        await modeProbe(args.target, args.port, pathsToTest, args.tls);
    } else if (args.mode === 'auth') {
        await modeAuth(args.target, args.port, pathsToTest, args.tls);
    } else if (args.mode === 'fuzz') {
        await modeFuzz(args.target, args.port, pathsToTest, args.tls);
    } else {
        console.error(`Modalità sconosciuta: ${args.mode}`);
        process.exit(1);
    }

    console.log('[*] WebSocket audit completato');
}

main().catch(e => {
    console.error(`[!] Errore: ${e.message}`);
    process.exit(1);
});
