import joblib
import pandas as pd
import re
import requests
import json
from flask import Flask, request, jsonify

# Caricare il file di configurazione config.json
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# Estrarre le informazioni del modello dal JSON
cmd_injection_model = config["models"]["cmd_injection"]

# Inizializzare Flask
app = Flask(__name__)

# Funzione per inviare il payload al modello
def send_payload_to_model(data):
    if cmd_injection_model["active"]:
        url = f'http://{cmd_injection_model["IP"]}:{cmd_injection_model["porta"]}{cmd_injection_model["endpoint"]}'
        headers = {"Content-Type": "application/json"}

        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Failed to get response from model."}
        except Exception as e:
            return {"error": str(e)}

# Funzione per processare i dati e inviare la richiesta al modello
@app.route('/process_request', methods=['POST'])
def process_request():
    try:
        # Ricevere i dati JSON dalla richiesta
        data = request.json

        # Verificare che ci siano i campi necessari
        required_fields = ["datetime", "ip_src", "payload", "http_method"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        # Inviare i dati al modello
        model_response = send_payload_to_model(data)

        # Restituire la risposta dal modello
        return jsonify(model_response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Avviare il server Flask per catturare richieste
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)  # Cambiare la porta a seconda delle esigenze
