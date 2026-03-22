#!/usr/bin/env python3
"""
mqtt_audit.py — MQTT Broker Security Audit
Uso: python3 mqtt_audit.py <target> [--port 1883] [--user u] [--pass p] [--tls]
"""

import argparse
import sys
import time
import json
import re
import threading
import queue

def check_paho():
    try:
        import paho.mqtt.client as mqtt
        return mqtt
    except ImportError:
        return None

SENSITIVE_PATTERNS = [
    r'password', r'passwd', r'secret', r'token', r'api.?key',
    r'credential', r'auth', r'private.?key', r'access.?key',
    r'session', r'jwt', r'bearer', r'apikey',
]

SENSITIVE_TOPICS = [
    'cmd/', 'set/', 'control/', 'actuator/', 'command/',
    'write/', 'action/', 'execute/', 'trigger/',
    '$SYS/broker/clients/connected',
]

def find_sensitive(text):
    for pat in SENSITIVE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False

def run_mqtt_audit(target, port, username=None, password=None, use_tls=False, timeout=12):
    mqtt = check_paho()
    if not mqtt:
        print("[!] paho-mqtt non installato. Installa con: pip3 install paho-mqtt")
        sys.exit(1)

    results = {
        "anonymous_access": False,
        "topics": [],
        "sensitive_messages": [],
        "sys_access": False,
        "write_access": [],
        "credentials_used": username is not None,
    }

    msg_queue = queue.Queue()
    connect_result = [None]
    connected_event = threading.Event()

    def on_connect(client, userdata, flags, rc):
        connect_result[0] = rc
        connected_event.set()
        if rc == 0:
            if username is None:
                print(f"[FOUND:HIGH]  Connessione anonima riuscita a {target}:{port}")
                results["anonymous_access"] = True
            else:
                print(f"[*] Connesso con {username}:{password}")
            # Subscribe topics
            client.subscribe("#", qos=0)
            client.subscribe("$SYS/#", qos=0)
        else:
            rc_msgs = {
                1: "Protocollo non accettato",
                2: "ID client rifiutato",
                3: "Broker non disponibile",
                4: "Credenziali errate",
                5: "Non autorizzato",
            }
            print(f"[ ] Connessione rifiutata: {rc_msgs.get(rc, f'rc={rc}')}")

    def on_message(client, userdata, msg):
        topic = msg.topic
        try:
            payload = msg.payload.decode('utf-8', errors='replace')
        except Exception:
            payload = str(msg.payload)
        msg_queue.put((topic, payload))

    def on_disconnect(client, userdata, rc):
        pass

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    if username:
        client.username_pw_set(username, password)

    if use_tls:
        try:
            import ssl
            client.tls_set(cert_reqs=ssl.CERT_NONE)
            client.tls_insecure_set(True)
            print(f"[*] TLS abilitato")
        except Exception as e:
            print(f"[!] TLS setup fallito: {e}")

    try:
        client.connect(target, port, keepalive=30)
    except Exception as e:
        print(f"[ ] Connessione fallita: {e}")
        return results

    client.loop_start()

    if not connected_event.wait(timeout=10):
        print(f"[ ] Timeout connessione a {target}:{port}")
        client.loop_stop()
        return results

    if connect_result[0] != 0:
        client.loop_stop()
        return results

    # Raccolta messaggi per 10 secondi
    print(f"[*] Raccolta messaggi per {timeout}s (topic: #, $SYS/#)...")
    deadline = time.time() + timeout
    seen_topics = set()

    while time.time() < deadline:
        try:
            topic, payload = msg_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        if topic not in seen_topics:
            seen_topics.add(topic)
            results["topics"].append(topic)
            is_sys = topic.startswith("$SYS")
            if is_sys:
                results["sys_access"] = True
            print(f"    Topic: {topic} | {payload[:80]}")

            # Cerca contenuto sensibile
            if find_sensitive(payload) or find_sensitive(topic):
                print(f"[FOUND:CRITICAL] Dati sensibili in topic: {topic} → {payload[:100]}")
                results["sensitive_messages"].append({"topic": topic, "payload": payload[:200]})

            # Prova parse JSON
            try:
                jdata = json.loads(payload)
                flat = json.dumps(jdata).lower()
                if find_sensitive(flat):
                    print(f"[FOUND:CRITICAL] JSON con dati sensibili: {topic}")
                    results["sensitive_messages"].append({"topic": topic, "json": jdata})
            except Exception:
                pass

    if results["sys_access"]:
        print(f"[FOUND:HIGH]  Accesso $SYS/ consentito — broker espone statistiche interne")

    # Test write su topic sensibili
    print(f"\n[*] Test PUBLISH su topic sensibili...")
    for stopic in SENSITIVE_TOPICS:
        try:
            rc = client.publish(stopic, payload="exa-dune-probe", qos=0)
            if rc.rc == 0:
                print(f"[FOUND:CRITICAL] PUBLISH riuscito su: {stopic}")
                results["write_access"].append(stopic)
            else:
                print(f"[ ]              PUBLISH negato: {stopic} (rc={rc.rc})")
        except Exception as e:
            print(f"[ ]              PUBLISH errore {stopic}: {e}")

    client.loop_stop()
    client.disconnect()

    # Summary
    print(f"\n[*] === Riepilogo MQTT Audit ===")
    print(f"    Accesso anonimo: {'SI' if results['anonymous_access'] else 'NO'}")
    print(f"    Topic visti: {len(results['topics'])}")
    print(f"    Accesso $SYS: {'SI' if results['sys_access'] else 'NO'}")
    print(f"    Topic sensibili con dati: {len(results['sensitive_messages'])}")
    print(f"    Topic con write access: {len(results['write_access'])}")
    if results["topics"]:
        print(f"    Esempi topic: {', '.join(list(results['topics'])[:5])}")

    return results

def main():
    parser = argparse.ArgumentParser(description="MQTT Broker Security Audit")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--user", default=None, help="Username MQTT")
    parser.add_argument("--pass", dest="password", default=None, help="Password MQTT")
    parser.add_argument("--tls", action="store_true", help="Usa TLS")
    parser.add_argument("--timeout", type=int, default=10, help="Secondi raccolta messaggi")
    args = parser.parse_args()

    print(f"[*] MQTT Audit — {args.target}:{args.port}")

    # Test anonimo prima
    if args.user is None:
        print("[*] Test 1: Accesso anonimo")
        results = run_mqtt_audit(args.target, args.port, None, None, args.tls, args.timeout)
        if not results["anonymous_access"] and args.port == 1883:
            # Prova porta TLS
            print("\n[*] Test 2: Porta TLS 8883")
            run_mqtt_audit(args.target, 8883, None, None, True, args.timeout)
    else:
        run_mqtt_audit(args.target, args.port, args.user, args.password, args.tls, args.timeout)

if __name__ == "__main__":
    main()
