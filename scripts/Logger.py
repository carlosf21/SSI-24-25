import os
import json
import logging
from datetime import datetime

log_dir = "../Logs"
os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")

logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

sensitive_keys = {
    "file_content",
    "encrypted_aes_key",
    "aes_key",
    "public_key",
    "encrypted_key",
    "file_path",
    "private_key",
    "cert",
    "server_cert",
    "client_cert",
    "nonce",
    "signature",
    "token",
    "session_key",
    "shared_key",
    "content",
}

def log_message(direction, message_json):
    """
    direction: 'SENT' ou 'RECEIVED'
    message_json: objeto JSON (dict ou str)
    """

    if isinstance(message_json, bytes):
        try:
            message_json = json.loads(message_json.decode())
        except:
            message_json = message_json.decode(errors="ignore")
    elif isinstance(message_json, str):
        try:
            message_json = json.loads(message_json)
        except:
            pass

    filtered = {}

    if isinstance(message_json, dict):
        for k, v in message_json.items():
            if k in sensitive_keys:
                continue
            if isinstance(v, str):
                if len(v) > 300 or v.strip().startswith(("MII", "MIIB", "UEsDBBQ")):
                    continue
            filtered[k] = v
    else:
        filtered = message_json

    log_line = {
        "direction": direction,
        "content": message_json
    }
    logging.info(f"{json.dumps(log_line, ensure_ascii=False, indent=2)}\n")

def log_warning(message):
    """
    message: mensagem de erro
    """
    logging.warning(f"{message}\n")

def log_error(message):
    """
    message: mensagem de erro
    """
    logging.error(f"{message}\n")

def log_exception(message):
    """
    message: mensagem de erro
    """
    logging.exception(f"{message}\n")

def log_critical(message):
    """
    message: mensagem de erro
    """
    logging.critical(f"{message}\n")

def log_debug(direction, message):
    """
    message: mensagem de erro
    """
    log_line = {
        "direction": direction,
        "content": message
    }
    logging.debug(f"{json.dumps(log_line, ensure_ascii=False, indent=2)}\n")