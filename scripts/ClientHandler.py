import os
import json
import base64
import uuid
from MessageFormat import *
from DatabaseHandler import *

def client_handler(msg_dict, user_id):
    action = msg_dict.get("action")

    if action == "add":
        print(f"Recebido ficheiro de {user_id}: {msg_dict['file']}")

        return msg_dict
    
    elif action == "list":
        print("Recebido list request de %s" % user_id)
        return msg_dict
        
    elif action == "ready":
        return make_ready_reply()

    elif action == "exit":
        return make_exit_reply()
    
    elif action == "share":
        print("Recebido share request de %s" % user_id)
        return msg_dict
    
    elif action == "delete":
        print("Recebido delete request de %s" % user_id)
        return msg_dict
    
    elif action == "replace":
        print("Recebido replace request de %s" % user_id)
        return msg_dict
    
    elif action == "details":
        print("Recebido details request de %s" % user_id)
        return msg_dict
    
    elif action == "revoke":
        print("Recebido revoke request de %s" % user_id)
        return msg_dict
    
    elif action == "read":
        print("Recebido read request de %s" % user_id)
        return msg_dict
    
    elif action == "group create":
        print("Recebido create request de %s" % user_id)
        return msg_dict
    
    elif action == "group delete":
        print("Recebido delete request de %s" % user_id)
        return msg_dict
    
    elif action == "group add-user":
        print("Recebido add-user request de %s" % user_id)
        return msg_dict
    
    elif action == "group delete-user":
        print("Recebido delete-user request de %s" % user_id)
        return msg_dict
    
    elif action == "group list":
        print("Recebido list request de %s" % user_id)
        return msg_dict
    
    elif action == "group add":
        print("Recebido add request de %s" % user_id)
        return msg_dict

    else:
        return {"action": action, "status": "error", "msg": "Ação desconhecida"}