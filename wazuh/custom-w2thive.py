#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests
import time

# Wazuh calls this script with: alert_file, api_key, hook_url
alert_file = sys.argv[1]
api_key = sys.argv[2]
hook_url = sys.argv[3]

# Minimum Wazuh rule level to forward. Adjust up to reduce noise later.
LVL_THRESHOLD = 7

with open(alert_file) as f:
    alert_json = json.load(f)

alert = alert_json.get('rule', {})
level = alert.get('level', 0)

if level < LVL_THRESHOLD:
    sys.exit(0)

description = alert_json.get('full_log', 'No description available')
rule_desc = alert.get('description', 'Wazuh Alert')
agent_name = alert_json.get('agent', {}).get('name', 'unknown')
src_ip = alert_json.get('data', {}).get('srcip') or alert_json.get('data', {}).get('src_ip')

observables = []
if src_ip:
    observables.append({
        "dataType": "ip",
        "data": src_ip,
        "message": "Source IP extracted from Wazuh alert",
        "tags": ["wazuh"],
        "ioc": True
    })

payload = {
    "type": "wazuh-alert",
    "source": "wazuh",
    "sourceRef": str(alert_json.get('id', str(int(time.time())))),
    "title": f"[Wazuh] {rule_desc} (agent: {agent_name})",
    "description": f"**Rule level:** {level}\n\n**Agent:** {agent_name}\n\n**Log:**\n```\n{description}\n```",
    "severity": 2 if level < 10 else 3,
    "tags": ["wazuh", f"level-{level}", f"agent-{agent_name}"],
    "tlp": 2,
    "pap": 2,
    "status": "New",
    "observables": observables
}

headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

try:
    resp = requests.post(f"{hook_url}/api/v1/alert", headers=headers, json=payload, timeout=10)
    resp.raise_for_status()
except Exception as e:
    sys.stderr.write(f"Error sending alert to TheHive: {e}\n")
    sys.exit(1)

alert_response = resp.json()
alert_id = alert_response.get("_id")

# Auto-promote critical alerts (level 12+) straight to a case
CRITICAL_THRESHOLD = 10
if level >= CRITICAL_THRESHOLD and alert_id:
    try:
        promote_resp = requests.post(
            f"{hook_url}/api/v1/alert/{alert_id}/case",
            headers=headers,
            timeout=10
        )
        promote_resp.raise_for_status()
    except Exception as e:
        sys.stderr.write(f"Alert created but auto-promote to case failed: {e}\n")


sys.exit(0)