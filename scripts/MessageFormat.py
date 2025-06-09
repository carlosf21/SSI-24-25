import json
import base64
from datetime import datetime
from DataStruct import *


def make_ready_msg(user="User X (SSI Vault Client X)", msg="msg example"):
    return {
        "action": "ready",
        "user": user,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_ready_reply(status="success", msg="Conexão estabelecida! Servidor pronto para receber comandos."):
    return {
        "action": "ready",
        "status": status,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_exit_msg(user="User X (SSI Vault Client X)", msg="msg example"):
    return {
    "action": "exit",
    "user": user,
    "msg": msg,
    "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_exit_reply(status="success", msg="Sessão terminada."):
    return {
        "action": "exit",
        "status": status,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_add_msg(
    file_name="file.txt",
    file_size=123,
    file_content=b"file content",
    encrypted_aes_key={"user": "encrypted_key"},
    users={"User X (SSI Vault Client X)": "W"},
    msg="Requested file upload"
):
    return {
        "action": "add",
        "users": users,
        "file": file_name,
        "file_content": file_content,
        "file_size": file_size,
        "encrypted_aes_key": encrypted_aes_key,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }
    
def make_list_msg(requester, target_type, target_id, msg):
    return {
        "action": "list",
        "requester": requester,      # Quem está a pedir a listagem
        "target_type": target_type,  # "user" ou "group"
        "target_id": target_id,      # ID do user ou grupo cujo cofre se quer listar
        "msg": msg                   # Mensagem adicional
    }

def make_add_reply(file_id, status="success", msg="Ficheiro guardado com sucesso!"):
    return {
        "action": "add",
        "status": status,
        "file_id": file_id,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_share_msg(permission, file_id="file.txt", user="User X (SSI Vault Client X)", msg="Share personal file", requester =  "User Y (SSI Vault Client Y)"):
    return{
        "action": "share",
        "file_id": file_id,
        "requester": requester,
        "user": user,
        "permission": permission,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_share_reply(status="success", msg="Ficheiro partilhado com sucesso!"):
    return{
        "action": "share",
        "file": file,
        "user": user,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_delete_msg(file="file.txt", user="User X (SSI Vault Client X)", msg="Delete file!"):
    return{
        "action": "delete",
        "file": file,
        "user": user,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_delete_reply(status="success", msg="Ficheiro apagado com sucesso!"):
    return{
        "action": "delete",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_replace_msg(file="file.txt", file_path="/newFile.txt", user="User X (SSI Vault Client X)", msg="Replace file!"):
    return{
        "action": "replace",
        "file": file,
        "file_path": file_path,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_replace_reply(status="success", msg="Ficheiro trocado com sucesso!", file_path="/newFile.txt", file ="file.txt", user="User X (SSI Vault Client X)"):
    return{
        "action": "replace",
        "file_path": file_path,
        "file": file,
        "user": user,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }
    
def make_read_msg(file_id="file.txt", requester="User X (SSI Vault Client X)", msg="Read file"):
    return {
        "action": "read",
        "file_id": file_id,
        "requester": requester,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_read_reply(status="success", msg="Ficheiro lido com sucesso!"):
    return{
        "action": "read",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_details_msg(file_id="file.txt", msg="File Details"):
    return{
        "action": "details",
        "file_id": file_id,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_details_reply(status="success", msg="Detalhes obtidos com sucesso!"):
    return{
        "action": "details",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_revoke_msg(file_id="file.txt", user="User X (SSI Vault Client X)", msg="Revogar acesso a ficheiro"):
    return{
        "action": "revoke",
        "user": user,
        "file_id": file_id,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_revoke_reply(status="success", msg="Acesso revogado com sucesso!"):
    return{
        "action": "revoke",
        "status": status,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupCreate_msg(group_name, msg="cria novo grupo"):
    return{
        "action": "create group",
        "group_name": group_name,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupCreate_reply(msg):
    return{
        "action": "create group",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupDelete_msg(group_id, user="User X (SSI Vault Client X)", msg="Apaga grupo"):
    return{
        "action": "delete group",
        "group_name": group_id,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupDelete_reply(msg="grupo apagado com sucesso!"):
    return{
        "action": "delete group",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupAddUser_msg(group_id, permissions, user="User X (SSI Vault Client X)", owner="User X (SSI Vault Client X)", msg="adicionar user ao grupo"):
    return{
        "action": "add user to group",
        "group_id": group_id,
        "permissions": permissions,
        "user": user,
        "owner": owner,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupAddUser_reply(status="success", msg="user adicionado com sucesso!"):
    return{
        "action": "add user to group",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupDeleteUser_msg(group_id, user="User X (SSI Vault Client X)", owner="User X (SSI Vault Client X)", msg="remover user do grupo"):
    return{
        "action": "remove user from group",
        "group_id": group_id,
        "user": user,
        "owner": owner,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupDeleteUser_reply(status="success", msg="user removido com sucesso!"):
    return{
        "action": "remove user from group",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupList_msg(msg="group list"):
    return{
        "action": "group list",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupList_reply(status="success", msg="grupos listados com sucesso!"):
    return{
        "action": "group list reply",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupAdd_msg(group_id, file_content, file_size, encrypted_key, file="file.txt", msg="adiconar ficheiro ao cofre do grupo"):
    return{
        "action": "add file to group vault",
        "group_id": group_id,
        "file": file,
        "file_content": file_content,
        "file_size": file_size, 
        "encrypted_key": encrypted_key,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }
    
def make_groupAdd_first_reply(status="success", public_keys= None, aes_key=None, file_id=None, group_id = None, msg="A adicionar ficheiro!"):
    return{
        "action": "add file to group vault",
        "public_keys": public_keys,
        "aes_key": aes_key,
        "group_id": group_id,
        "file_id": file_id,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }
    
def make_groupAdd_client_reply(status="success", aes_keys= None, group_id = None, file_id = None, msg="A adicionar ficheiro!"):
    return{
        "action": "add file to group vault reply",
        "aes_keys": aes_keys,
        "group_id": group_id,
        "file_id": file_id,
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }

def make_groupAdd_reply(status="success", msg="ficheiro adicionado com sucesso!"):
    return{
        "action": "add file to group vault final reply",
        "msg": msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    }