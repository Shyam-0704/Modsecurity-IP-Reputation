#!/usr/bin/env python3
import re
import json

log_file_path = '/var/log/apache2/modsec_audit.log'
output_json_path = '/var/www/html/modsec_data.json'

# Regex patterns
rx_a = re.compile(r'^--([a-zA-Z0-9]+)-A--')
rx_b = re.compile(r'^--([a-zA-Z0-9]+)-B--')
rx_h = re.compile(r'^--([a-zA-Z0-9]+)-H--')
rx_z = re.compile(r'^--([a-zA-Z0-9]+)-Z--')
rx_metadata = re.compile(r'\[client (?P<ip>[\d.]+)\].*?\[unique_id "(?P<uid>.*?)"\]')
rx_message = re.compile(r'\[msg "(.*?)"\]')
rx_rule_id = re.compile(r'\[id "(.*?)"\]')
rx_severity = re.compile(r'\[severity "(.*?)"\]')
rx_request = re.compile(r'^([A-Z]+) (.*?) HTTP')
rx_timestamp = re.compile(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)? [+\-]\d{4})\]')

entries = []
current_section = None
transaction = {}

with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        match_a = rx_a.match(line)
        match_b = rx_b.match(line)
        match_h = rx_h.match(line)
        match_z = rx_z.match(line)

        if match_a:
            # Start new transaction
            transaction = {
                'tid': match_a.group(1),
                'raw': [],
                'request': '',
                'metadata': '',
                'timestamp': 'unknown'
            }
            current_section = 'A'

        elif match_b:
            current_section = 'B'

        elif match_h:
            current_section = 'H'

        elif match_z:
            # Finalize and store transaction
            meta = transaction['metadata']
            msg_matches = rx_message.findall(meta)
            id_matches = rx_rule_id.findall(meta)
            sev_matches = rx_severity.findall(meta)
            meta_match = rx_metadata.search(meta)

            unique_id = meta_match.group('uid') if meta_match else transaction['tid']
            client_ip = meta_match.group('ip') if meta_match else "unknown"
            request_line = transaction['request'] or "unknown"

            severity_weights = {
                "CRITICAL": 10,
                "ERROR": 7,
                "WARNING": 4,
                "NOTICE": 2
            }
            threat_score = sum(severity_weights.get(sev.upper(), 1) for sev in sev_matches)

            entries.append({
                'unique_id': unique_id,
                'client_ip': client_ip,
                'timestamp': transaction['timestamp'],
                'request_line': request_line,
                'messages': msg_matches,
                'rule_ids': id_matches,
                'severities': sev_matches,
                'threat_score': threat_score
            })

            current_section = None
            transaction = {}

        elif current_section:
            transaction['raw'].append(line)

            if current_section == 'B':
                if not transaction['request']:
                    req_match = rx_request.match(line)
                    if req_match:
                        transaction['request'] = line
                ts_match = rx_timestamp.search(line)
                if ts_match and transaction['timestamp'] == 'unknown':
                    transaction['timestamp'] = ts_match.group(1)

            elif current_section == 'H':
                transaction['metadata'] += line + ' '

# Output to JSON
with open(output_json_path, 'w', encoding='utf-8') as out:
    json.dump(entries, out, indent=2)
