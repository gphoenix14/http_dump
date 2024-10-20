import subprocess
import csv
import argparse
import json
import os
import re
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw
import requests  # Import necessario per inviare richieste HTTP

# Caricare il file di configurazione config.json
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# Ottenere i modelli dal file di configurazione
models = config.get("models", {})

# Argparse per specificare la porta
parser = argparse.ArgumentParser(description='Capture HTTP requests on a specified port')
parser.add_argument('-p', '--port', type=int, required=True, help='Port to capture HTTP traffic')
args = parser.parse_args()

# Ottenere il percorso della directory di log dal file di configurazione
log_directory = config.get("output_log_directory", ".")

# Creare la directory di log se non esiste
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Generare il nome del file CSV di output
log_pattern = re.compile(r'log_(\d+)\.csv')
existing_ids = []

for filename in os.listdir(log_directory):
    match = log_pattern.match(filename)
    if match:
        existing_ids.append(int(match.group(1)))

if existing_ids:
    last_id = max(existing_ids)
else:
    last_id = 0

new_id = last_id + 1

output_file = os.path.join(log_directory, f'log_{new_id}.csv')

print(f"Output file: {output_file}")

# Preprocesso dei campi attivi nel file di configurazione
enabled_fields = {key: value for key, value in config["fields"].items() if value}

# Creare l'intestazione del file CSV basato sui campi attivi
csv_headers = list(enabled_fields.keys())

with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(csv_headers)

# Pre-calcolare i campi da catturare
capture_fields = set(csv_headers)

# Funzione per estrarre il payload da una query GET o POST
def estrai_payload(uri, payload, http_method):
    strings = []
    
    # Estrarre i valori delle query GET
    if 'GET' in http_method and '?' in uri:
        query_params = uri.split('?', 1)[1]
        pairs = query_params.split('&')
        for pair in pairs:
            value = pair.split('=', 1)[1] if '=' in pair else ''
            strings.append(value)

    # Estrarre i dati dal payload POST (considerando JSON)
    elif 'POST' in http_method and payload:
        try:
            json_data = json.loads(payload)
            for value in json_data.values():
                strings.append(value)
        except json.JSONDecodeError:
            pass  # Non è un payload JSON valido, ignora

    return strings

# Funzione per analizzare i pacchetti HTTP
def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            # Verificare che il pacchetto sia una richiesta dal client al server
            if packet[TCP].dport == args.port:
                # Decodificare il payload HTTP
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                if 'HTTP' in payload:
                    # Dizionario per i campi
                    row_dict = {}

                    # Estrazione delle informazioni
                    if 'datetime' in capture_fields:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        row_dict['datetime'] = timestamp

                    if 'ip_src' in capture_fields:
                        ip_src = packet[IP].src
                        row_dict['ip_src'] = ip_src

                    if 'src_port' in capture_fields:
                        src_port = packet[TCP].sport
                        row_dict['src_port'] = src_port

                    # Analisi della richiesta HTTP
                    lines = payload.split('\r\n')
                    request_line = lines[0] if len(lines) > 0 else ''
                    parts = request_line.split(' ')
                    http_method = parts[0] if len(parts) > 0 else ''
                    uri = parts[1] if len(parts) > 1 else ''

                    if 'http_method' in capture_fields:
                        row_dict['http_method'] = http_method

                    if 'endpoint' in capture_fields:
                        row_dict['endpoint'] = uri

                    # Unire query GET e dati POST nel campo payload
                    get_query = uri.split('?', 1)[1] if '?' in uri else ''
                    post_payload = payload.split('\r\n\r\n', 1)[1] if 'POST' in http_method and '\r\n\r\n' in payload else ''
                    full_payload = '&'.join(filter(None, [get_query, post_payload]))

                    if 'payload' in capture_fields:
                        row_dict['payload'] = full_payload

                    # Analisi degli header HTTP
                    headers = {}
                    for header_line in lines[1:]:
                        if ': ' in header_line:
                            key, value = header_line.split(': ', 1)
                            headers[key] = value

                    if 'referer' in capture_fields:
                        referer = headers.get('Referer', '')
                        row_dict['referer'] = referer

                    if 'user_agent' in capture_fields:
                        user_agent = headers.get('User-Agent', '')
                        row_dict['user_agent'] = user_agent

                    if 'cookie' in capture_fields:
                        cookie = headers.get('Cookie', '')
                        row_dict['cookie'] = cookie

                    # Creare la lista di valori per la riga, nell'ordine dei csv_headers
                    row = [row_dict.get(field, '') for field in csv_headers]

                    # Scrittura nel file CSV
                    with open(output_file, 'a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(row)

                    # Stampa sul terminale
                    print(f"Captured HTTP request: {row}")

                    # Estrarre il payload
                    extracted_strings = estrai_payload(uri, post_payload, http_method)

                    # Preparare il JSON da inviare al modello
                    model_data = {"strings": extracted_strings}
                    
                    # Inviare i dati ai modelli attivi
                    for model_name, model_info in models.items():
                        if model_info.get("active", False):
                            model_ip = model_info.get("IP", "localhost")
                            model_port = model_info.get("porta", 80)
                            model_endpoint = model_info.get("endpoint", "/")
                            url = f"http://{model_ip}:{model_port}{model_endpoint}"
                            headers = {"Content-Type": "application/json"}
                            try:
                                response = requests.post(url, headers=headers, json=model_data)
                                print(f"Risposta dal modello {model_name}: {response.text}")
                            except Exception as e:
                                print(f"Errore durante l'invio al modello {model_name}: {e}")

        except Exception as e:
            print(f"Error processing packet: {e}")

# Avviare lo sniffing per catturare i pacchetti HTTP sulla porta specificata
def start_sniffing():
    filter_str = f"tcp dst port {args.port} and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"
    print(f"Starting sniffing on port {args.port}...")

    sniff(filter=filter_str, prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
