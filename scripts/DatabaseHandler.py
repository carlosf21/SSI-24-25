import json
import base64
import uuid
import os
from MessageFormat import *
from DataStruct import *
from cryptography.hazmat.primitives import serialization
from IdGenerator import generate_group_id

DATABASE_DIR = "../Database"
USER_VAULTS_DIR = os.path.join(DATABASE_DIR, "user_vaults")
GROUP_VAULTS_DIR = os.path.join(DATABASE_DIR, "group_vaults")
USER_JSON_DIR = os.path.join(DATABASE_DIR, "user_database.json")
GROUP_JSON_DIR = os.path.join(DATABASE_DIR, "group_database.json")

def load_json_databases():
    global user_db, group_db
    with open(USER_JSON_DIR, "r") as f:
        user_db = json.load(f)
    with open(GROUP_JSON_DIR, "r") as f:
        group_db = json.load(f)

def ensure_database_files():
    for fname in [USER_JSON_DIR, GROUP_JSON_DIR]:
        if not os.path.exists(fname):
            with open(fname, "w") as f:
                f.write("{}")

def save_user_db():
    with open(USER_JSON_DIR, "w") as f:
        json.dump(user_db, f, indent=2)

def save_group_db():
    with open(GROUP_JSON_DIR, "w") as f:
        json.dump(group_db, f, indent=2)

def create_vault_dirs():
    """Create the necessary directories for user and group vaults."""
    msg = "Directories created:"
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR, mode=0o700)
        msg += (f" {DATABASE_DIR}")
    if not os.path.exists(USER_VAULTS_DIR):
        os.makedirs(USER_VAULTS_DIR, mode=0o700)
        msg += (f" {USER_VAULTS_DIR}")
    if not os.path.exists(GROUP_VAULTS_DIR):
        os.makedirs(GROUP_VAULTS_DIR, mode=0o700)
        msg += (f" {GROUP_VAULTS_DIR}")
    print(msg) if msg != "Directories created:" else None

def create_vault(vault_name, vault_type):
    """Create a vault directory for a user or group."""
    if vault_type == "user":
        vault_path = os.path.join(USER_VAULTS_DIR, vault_name)
    elif vault_type == "group":
        vault_path = os.path.join(GROUP_VAULTS_DIR, vault_name)
    else:
        raise ValueError("Invalid vault type. Use 'user' or 'group'.")
    
    if not os.path.exists(vault_path):
        os.makedirs(vault_path)
        print(f"Vault created: {vault_path}")
    else:
        print(f"Vault already exists: {vault_path}")

# --- HANDLER FUNCTIONS --- #

def register_user_if_needed(user_name, public_key_pem=None):
    """
    Regista um utilizador na base de dados se ainda não existir,
    ou atualiza a chave pública se já existir.
    """
    load_json_databases()
    if user_name not in user_db:
        user_db[user_name] = {
            "vault_path": os.path.join(USER_VAULTS_DIR, user_name),
            "groups": {},
            "files": [],
            "public_key": public_key_pem
        }
        print(f"[INFO] Utilizador '{user_name}' registado com nova chave pública.")
    else:
        if user_db[user_name].get("public_key") != public_key_pem:
            user_db[user_name]["public_key"] = public_key_pem
            print(f"[INFO] Chave pública de '{user_name}' atualizada.")

    save_user_db()
    
def get_user_public_key(user_name):
    """
    Retorna a chave pública do utilizador especificado, descodificada de Base64.
    """
    load_json_databases()

    if user_name in user_db:
        public_key_base64 = user_db[user_name].get("public_key")
        if public_key_base64:
            # Descodifica a chave pública de volta para bytes
            return base64.b64decode(public_key_base64.encode('utf-8'))
        else:
            print(f"[ERRO] Chave pública não encontrada para o utilizador '{user_name}'.")
            return None
    else:
        print(f"[ERRO] Utilizador '{user_name}' não encontrado na base de dados.")
        return None


def handle_add(user_name, file_info):
    try:
        load_json_databases()
        
        # Preparar as informações do ficheiro para armazenar
        file_info = {
            "file": file_info["file"],  # Nome do ficheiro
            "file_id": file_info["file_id"],    # ID único para o ficheiro
            "file_size": file_info["file_size"],  # Tamanho do ficheiro
            "encrypted_aes_key": file_info["encrypted_aes_key"],  # Chave AES encriptada
            "users": {user_name: "RW"}  # Permissão de leitura e escrita para o utilizador
        }

        # Adiciona o ficheiro à base de dados do utilizador
        user_db[user_name]["files"].append(file_info)

        save_user_db()
        ensure_database_files()
        
        return file_info["file_id"]
    
    except Exception as e:
        print(f"[ERRO] Falha ao adicionar ficheiro: {e}")
        return None



def handle_list(response_dict, user_database_path, group_database_path):
    target_type = response_dict["target_type"]
    

    target_id = response_dict["target_id"]
        
    requesting_user = response_dict["requester"]

    if target_type not in ["user", "group"]:
        return f"[ERRO] Tipo de destino inválido: {target_type}.".encode()

    try:
        with open(user_database_path if target_type == "user" else group_database_path, "r") as f:
            database = json.load(f)
    except FileNotFoundError:
        return f"[ERRO] Base de dados de {target_type} não encontrada.".encode()
    except json.JSONDecodeError:
        return f"[ERRO] Erro ao ler a base de dados de {target_type}.".encode()

    if target_id not in database:
        return f"[ERRO] Vault de {target_type} '{target_id}' não existe.".encode()
        
    vault = database[target_id]
    
    files = vault.get("files", [])
    print(f"Files in vault: {files}")

    if target_type == "user":
        accessible_files = [
            file for file in files if requesting_user in file.get("users", {})
        ]
        if not accessible_files:
            return f"Vault de {target_type} '{target_id}' não contém ficheiros acessíveis por {requesting_user}.".encode()
    else:
        # Para grupos, verificamos se o utilizador é membro do grupo
        if requesting_user not in vault.get("members", {}):
            return f"Utilizador '{requesting_user}' não é membro do grupo '{target_id}'.".encode()
        else:
            accessible_files = files

    formatted_list = f"Ficheiros no vault do {target_type} '{target_id}' acessíveis por '{requesting_user}':\n"
    for i, file in enumerate(accessible_files, 1):
        formatted_list += f"  {i}. {file['file']} (ID: {file['file_id']}, {file['file_size']} bytes)\n"

    return formatted_list.encode()


def handle_share(owner, file_id, target_user, permission):
    load_json_databases()

    if owner not in user_db:
        return f"[ERRO] Utilizador '{owner}' não encontrado na base de dados."

    files = user_db[owner].get("files", [])
    
    # Encontrar o ficheiro com o file_id correspondente
    for file in files:
        if file["file_id"] == file_id:
            if "users" not in file:
                file["users"] = {}

            file["users"][target_user] = permission
            save_user_db()
            
            if target_user not in user_db:
                return f"[ERRO] Utilizador '{target_user}' não encontrado na base de dados."
            
            target_public_key_pem = user_db[target_user].get("public_key")
            if not target_public_key_pem:
                return f"[ERRO] Chave pública não encontrada para o utilizador '{target_user}'."

            # Carregar a chave pública PEM corretamente
            try:
                target_public_key = serialization.load_pem_public_key(target_public_key_pem.encode())
            except Exception as e:
                return f"[ERRO] Falha ao carregar a chave pública: {e}"

            # Buscar chave AES encriptada do owner
            encrypted_aes_key_b64 = file["encrypted_aes_key"].get(owner)
            if not encrypted_aes_key_b64:
                return f"[ERRO] Chave AES encriptada não encontrada para o utilizador '{owner}'."

            try:
                encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            except Exception as e:
                return f"[ERRO] Chave AES encriptada inválida: {e}"
            
            pem_bytes = target_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            base64_pem = base64.b64encode(pem_bytes).decode()

            return base64_pem, encrypted_aes_key


    return f"[ERRO] Ficheiro com ID '{file_id}' não encontrado para o utilizador '{owner}'."


def finalize_share(owner, file_id, target_user, encrypted_aes_key_b64):
    try:
        load_json_databases()

        if owner not in user_db:
            return f"[ERRO] Utilizador '{owner}' não encontrado na base de dados."

        # Verificar se o ficheiro existe no vault do proprietário
        files = user_db[owner].get("files", [])
        file_to_share = None
        for file in files:
            if file["file_id"] == file_id:
                file_to_share = file
                break

        if not file_to_share:
            return f"[ERRO] Ficheiro com ID '{file_id}' não encontrado no vault de {owner}."

        # Verificar se o utilizador de destino existe na base de dados
        if target_user not in user_db:
            return f"[ERRO] Utilizador '{target_user}' não encontrado na base de dados."

        # Armazenar a chave AES encriptada para o utilizador compartilhado
        if "encrypted_aes_key" not in file_to_share:
            file_to_share["encrypted_aes_key"] = {}

        file_to_share["encrypted_aes_key"][target_user] = encrypted_aes_key_b64

        # Salvar as alterações na base de dados do utilizador
        save_user_db()

        # Confirmar o sucesso do compartilhamento
        return f"[INFO] Ficheiro '{file_id}' compartilhado com sucesso para o utilizador '{target_user}'."

    except Exception as e:
        return f"[ERRO] Falha ao finalizar o compartilhamento: {str(e)}"





def handle_read(client_id, file_id):
    load_json_databases()

    if file_id.startswith("FU"):
        db = user_db
        vault_base_dir = USER_VAULTS_DIR
    elif file_id.startswith("FG"):
        db = group_db
        vault_base_dir = GROUP_VAULTS_DIR
    else:
        return f"[ERRO] Prefixo de file_id inválido: {file_id}"

    for vault_id, vault_data in db.items():
        files = vault_data.get("files", [])

        for file in files:
            if file["file_id"] == file_id:
                # Verifica permissões
                if file_id.startswith("FU"):
                    permissions = file.get("users", {})
                    user_permission = permissions.get(client_id)
                    if user_permission not in ("R", "RW"):
                        return f"[ERRO] Utilizador '{client_id}' não tem permissão para ler o ficheiro {file_id}."
                else:  # FG
                    members = vault_data.get("members", {})
                    user_permission = members.get(client_id)
                    if user_permission not in ("R", "RW"):
                        return f"[ERRO] Utilizador '{client_id}' não tem permissão para ler o ficheiro {file_id} no grupo {vault_id}."

                file_path = os.path.join(vault_base_dir, vault_id, file["file_id"])
                if not os.path.exists(file_path):
                    return f"[ERRO] Ficheiro {file_id} não encontrado em {vault_id}."

                try:
                    with open(file_path, "rb") as f:
                        file_content = f.read()
                        
                    file_content = base64.b64encode(file_content)
                except:
                    return f"[ERRO] Erro ao ler ficheiro {file_id}"

                # Encontra e codifica a chave AES encriptada
                encrypted_key = file.get("encrypted_aes_key", {}).get(client_id)
                if not encrypted_key:
                    return f"[ERRO] Chave AES não encontrada para utilizador '{client_id}' no ficheiro {file_id}."

                if isinstance(file_content, str):
                    file_content = file_content.encode()

                if isinstance(encrypted_key, str):
                    encrypted_aes_key = encrypted_key.encode()

                # Codificando os dados binários para base64
                file_content_b64 = base64.b64encode(file_content)  # Base64 ainda retorna bytes
                encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key)  # Base64 ainda retorna bytes
                print(f"[INFO] Ficheiro '{file_id}' lido com sucesso para o utilizador '{client_id}'.")
                return file_content_b64, encrypted_aes_key_b64

    return f"[ERRO] Ficheiro '{file_id}' não encontrado."



def handle_revoke(requester, file_id, target_user):
    import json

    with open(USER_JSON_DIR, "r") as f:
        db = json.load(f)

    if requester not in db:
        raise Exception("Requester não existe.")
    if target_user not in db:
        raise Exception("Target user não existe.")

    requester_data = db[requester]
    files = requester_data.get("files", [])

    # Encontra o ficheiro com o file_id correspondente
    file_entry = next((f for f in files if f["file_id"] == file_id), None)
    if not file_entry:
        raise Exception("Ficheiro não encontrado.")

    # Verifica se o utilizador a revogar tem acesso
    if target_user not in file_entry["users"]:
        raise Exception("Utilizador não tem acesso ao ficheiro.")

    # Remove o utilizador e a respetiva chave AES encriptada
    del file_entry["users"][target_user]
    if target_user in file_entry["encrypted_aes_key"]:
        del file_entry["encrypted_aes_key"][target_user]

    with open(USER_JSON_DIR, "w") as f:
        json.dump(db, f, indent=2)

    return f"Acesso do utilizador {target_user} revogado com sucesso para o ficheiro {file_id}."


def handle_group_create(requester, group_name):
    """
    Cria um grupo e o respetivo vault se o nome não existir ainda.
    O utilizador que cria o grupo é adicionado como administrador.
    """
    load_json_databases()

    requester_id = requester
    group_id = generate_group_id()

    if group_id in group_db:
        return f"[ERRO] O grupo '{group_id}' já existe."

    if requester_id not in user_db:
        return f"[ERRO] Utilizador '{requester}' não encontrado na base de dados."

    # Criar o vault físico para o grupo
    create_vault(group_id, "group")

    # Adicionar entrada à base de dados do grupo
    group_db[group_id] = {
        "vault_path": os.path.join(GROUP_VAULTS_DIR, group_id),
        "name": group_name,
        "admin": requester_id,
        "members": {requester_id : "RW"},
        "files": []
    }

    # Atualizar lista de grupos do utilizador
    user_db[requester_id]["groups"][group_id] = "RW"

    save_group_db()
    save_user_db()

    return f"[INFO] Grupo '{group_name}' com id {group_id} criado com sucesso com '{requester}' como administrador."


def handle_group_delete(requester_id, group_id):
    """
    Remove um grupo e o respetivo vault, apenas se o requester for o administrador.
    """
    load_json_databases()

    if group_id not in group_db:
        return f"[ERRO] O grupo com ID '{group_id}' não existe."

    group_info = group_db[group_id]

    if group_info["admin"] != requester_id:
        return f"[ERRO] Apenas o administrador pode apagar o grupo '{group_info['name']}'."

    # Remover grupo da lista de grupos dos membros
    for member_id in group_info["members"]:
        if member_id in user_db and group_id in user_db[member_id]["groups"]:
            del user_db[member_id]["groups"][group_id]

    # Remover o vault físico
    vault_path = group_info["vault_path"]
    if os.path.exists(vault_path):
        try:
            import shutil
            shutil.rmtree(vault_path)
        except Exception as e:
            return f"[ERRO] Falha ao remover o vault do grupo: {str(e)}"

    # Remover grupo da base de dados
    group_name = group_info["name"]
    del group_db[group_id]

    save_group_db()
    save_user_db()

    return f"[INFO] Grupo '{group_name}' com ID '{group_id}' removido com sucesso."


def handle_group_add_user(admin_id, group_id, user_to_add, permissions):
    """
    Adiciona um utilizador a um grupo com permissões específicas, se o pedido for feito por um administrador.
    Prepara o compartilhamento dos ficheiros do grupo, retornando a chave pública e chaves AES encriptadas.
    """
    load_json_databases()
    if group_id not in group_db:
        return f"[ERRO] Grupo '{group_id}' não encontrado."

    group_info = group_db[group_id]

    if group_info.get("admin") != admin_id:
        return f"[ERRO] O utilizador '{admin_id}' não é administrador do grupo '{group_id}'."
    
    # Validação das permissões
    valid_permissions = {"R", "W", "RW"}
    if permissions not in valid_permissions:
        return f"[ERRO] Permissões inválidas: {permissions}. Use apenas 'R', 'W' ou 'RW'."
    # Verificar se o utilizador a adicionar existe na base de dados
    if user_to_add not in user_db:
        return f"[ERRO] Utilizador '{user_to_add}' não encontrado na base de dados."

    # Obter a chave pública do utilizador a adicionar
    target_public_key_pem = user_db[user_to_add].get("public_key")
    if not target_public_key_pem:
        return f"[ERRO] Chave pública não encontrada para o utilizador '{user_to_add}'."

    # Carregar a chave pública PEM
    try:
        target_public_key = serialization.load_pem_public_key(target_public_key_pem.encode())
    except Exception as e:
        return f"[ERRO] Falha ao carregar a chave pública: {e}"

    # Adicionar utilizador aos membros com permissões
    group_info.setdefault("members", {})[user_to_add] = permissions

    # Atualizar a base de dados de utilizadores para refletir a associação ao grupo
    user_db[user_to_add].setdefault("groups", {})[group_id] = permissions

    save_group_db()
    save_user_db()

    # Obter chaves AES encriptadas dos ficheiros do grupo (apenas do admin)
    aes_keys = {}
    files = group_info.get("files", [])
    for file in files:
        encrypted_aes_key_b64 = file.get("encrypted_aes_key", {}).get(admin_id)
        if encrypted_aes_key_b64:
            try:
                encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                aes_keys[file["file_id"]] = base64.b64encode(encrypted_aes_key).decode('utf-8')
            except Exception as e:
                print(f"[AVISO] Chave AES inválida para o ficheiro {file['file_id']}: {e}")
                continue

    # Retornar a chave pública em formato base64 e as chaves AES
    pem_bytes = target_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    base64_pem = base64.b64encode(pem_bytes).decode()
    return base64_pem, aes_keys

def finalize_group_add_user(admin_id, group_id, user_to_add, encrypted_aes_keys_b64):
    """
    Finaliza o compartilhamento de ficheiros de um grupo com um novo utilizador,
    atualizando as chaves AES encriptadas na base de dados.
    """
    try:
        load_json_databases()

        if group_id not in group_db:
            return f"[ERRO] Grupo '{group_id}' não encontrado."

        group_info = group_db[group_id]

        if group_info.get("admin") != admin_id:
            return f"[ERRO] O utilizador '{admin_id}' não é administrador do grupo '{group_id}'."

        if user_to_add not in group_info.get("members", {}):
            return f"[ERRO] O utilizador '{user_to_add}' não é membro do grupo '{group_id}'."

        # Verificar se o utilizador existe na base de dados
        if user_to_add not in user_db:
            return f"[ERRO] Utilizador '{user_to_add}' não encontrado na base de dados."

        # Atualizar as chaves AES encriptadas para os ficheiros do grupo
        files = group_info.get("files", [])
        updated_files = 0
        for file in files:
            file_id = file["file_id"]
            if file_id in encrypted_aes_keys_b64:
                if "encrypted_aes_key" not in file:
                    file["encrypted_aes_key"] = {}
                file["encrypted_aes_key"][user_to_add] = encrypted_aes_keys_b64[file_id]
                updated_files += 1

        # Salvar as alterações na base de dados do grupo
        save_group_db()

        return f"[INFO] {updated_files} ficheiros do grupo '{group_id}' compartilhados com sucesso para o utilizador '{user_to_add}'."

    except Exception as e:
        return f"[ERRO] Falha ao finalizar o compartilhamento: {str(e)}"


def handle_group_remove_user(admin_id, group_id, user_to_remove):
    """
    Remove um utilizador de um grupo, se o pedido for feito por um administrador.
    """
    load_json_databases()

    if group_id not in group_db:
        return f"[ERRO] Grupo '{group_id}' não encontrado."

    group_info = group_db[group_id]

    if group_info.get("admin") != admin_id:
        return f"[ERRO] O utilizador '{admin_id}' não é administrador do grupo '{group_id}'."

    if user_to_remove not in group_info.get("members", {}):
        return f"[ERRO] O utilizador '{user_to_remove}' não é membro do grupo '{group_id}'."

    # Remove o utilizador da lista de membros do grupo
    del group_info["members"][user_to_remove]

    # Remove o grupo da lista de grupos do utilizador
    if user_to_remove in user_db and group_id in user_db[user_to_remove].get("groups", []):
        del user_db[user_to_remove]["groups"][group_id]


    save_group_db()
    save_user_db()

    return f"[INFO] Utilizador '{user_to_remove}' removido do grupo '{group_id}' com sucesso."

def handle_group_list(requester_id):
    # Obtém os grupos do utilizador
    user_groups = user_db.get(requester_id, {}).get("groups", {})

    if not user_groups:
        result = "Não pertence a nenhum grupo."
    else:
        group_lines = []
        for group_id, permission in user_groups.items():
            group_name = group_db.get(group_id, {}).get("name", "Grupo sem nome")
            group_lines.append(f"{group_name} (ID: {group_id}, Permissão: {permission})")
        result = "; ".join(group_lines)
    return result


def handle_group_add(user_name, msg_dict, file_id):
    load_json_databases()

    group_id = msg_dict.get("group_id")
    file_name = msg_dict.get("file")
    file_size = msg_dict.get("file_size")
    encrypted_aes_key = msg_dict.get("encrypted_key")

    if group_id not in group_db:
        return f"[ERRO] Grupo '{group_id}' não existe."

    group = group_db[group_id]

    # Verificar se o utilizador é membro com permissão de escrita
    member_permissions = group.get("members", {}).get(user_name)
    if member_permissions not in ["RW", "W"]:
        return f"[ERRO] O utilizador '{user_name}' não tem permissões de escrita no grupo '{group['name']}'."

    if "files" not in group:
        group["files"] = []

    file_entry = {
        "file": file_name,
        "file_id": file_id,
        "file_size": file_size,
        "encrypted_aes_key": encrypted_aes_key,
    }

    group["files"].append(file_entry)
    
    file_path = os.path.join(GROUP_VAULTS_DIR, group_id, file_id)
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    try:
        with open(file_path, "wb") as f:
            f.write(base64.b64decode(msg_dict["file_content"]))
    except Exception as e:
        print(f"[{user_name}] Erro ao escrever o ficheiro: {e}")
        return (b"[ERRO] Erro ao escrever o ficheiro.")

    save_group_db()
    public_keys = {}
    for member in group.get("members", {}):
        public_key_pem = user_db.get(member, {}).get("public_key")
        if public_key_pem:
            try:
                pem_bytes = public_key_pem.encode()
                base64_pem = base64.b64encode(pem_bytes).decode()
                public_keys[member] = base64_pem
            except Exception as e:
                print(f"[AVISO] Erro ao processar chave pública de {member}: {e}")
                continue
    
    print(f'AQUI:{encrypted_aes_key.get(user_name)}')
    return public_keys, encrypted_aes_key.get(user_name)


def handle_group_add_finalize(group_id, file_id, encrypted_keys_dict):
    try:
        load_json_databases()

        if group_id not in group_db:
            return f"[ERRO] Grupo '{group_id}' não encontrado."

        group = group_db[group_id]
        files = group.get("files", [])

        # Procurar o ficheiro com o file_id correspondente
        for file in files:
            if file.get("file_id") == file_id:
                # Criar ou atualizar o campo encrypted_aes_key
                if "encrypted_aes_key" not in file:
                    file["encrypted_aes_key"] = {}

                for user, encrypted_key_b64 in encrypted_keys_dict.items():
                    file["encrypted_aes_key"][user] = encrypted_key_b64

                save_group_db()
                return f"[INFO] Ficheiro {file_id}' adicionado ao grupo '{group_id}'."

        return f"[ERRO] Ficheiro '{file_id}' não encontrado no grupo '{group_id}'."

    except Exception as e:
        return f"[ERRO] Ocorreu um erro ao finalizar a adição do ficheiro: {str(e)}"


def handle_delete(file_id, user_id):
    load_json_databases()

    # Ficheiro pessoal (FU)
    if file_id.startswith("FU"):
        file_owner = None
        file_found = None

        # Procurar ficheiro entre todos os utilizadores
        for uid, udata in user_db.items():
            for f in udata.get("files", []):
                if f["file_id"] == file_id:
                    file_owner = uid
                    file_found = f
                    break
            if file_found:
                break

        if not file_found:
            return f"[ERRO] Ficheiro {file_id} não encontrado."

        if file_owner == user_id:
            # É o dono — remover completamente
            file_path = os.path.join(user_db[file_owner]["vault_path"], file_found["file"])
            try:
                os.remove(file_path)
                print(f"[INFO] Ficheiro {file_id} removido com sucesso.")
            except FileNotFoundError:
                pass

            user_db[file_owner]["files"] = [
                f for f in user_db[file_owner]["files"] if f["file_id"] != file_id
            ]
            save_user_db()
            return f"[INFO] Ficheiro {file_id} removido completamente do cofre de {user_id}."
        else:
            # Não é o dono — remover apenas permissão
            if "users" in file_found and user_id in file_found["users"]:
                del file_found["users"][user_id]
                if "encrypted_aes_key" in file_found and user_id in file_found["encrypted_aes_key"]:
                    del file_found["encrypted_aes_key"][user_id]
                save_user_db()
                return f"[INFO] Acesso de {user_id} ao ficheiro {file_id} removido."
            else:
                return f"[ERRO] O utilizador {user_id} não tem acesso ao ficheiro {file_id}."

    # Ficheiro de grupo (FG)
    elif file_id.startswith("FG"):
        group_id = None
        file_found = None

        # Procurar o ficheiro no grupo
        for gid, group in group_db.items():
            for f in group.get("files", []):
                if f["file_id"] == file_id:
                    group_id = gid
                    file_found = f
                    break
            if file_found:
                break

        if not file_found:
            return f"[ERRO] Ficheiro {file_id} não encontrado em grupos."

        group = group_db[group_id]
        is_admin = group["admin"] == user_id

        if is_admin:
            # Admin remove completamente
            file_path = os.path.join(group["vault_path"], file_found["file"])
            try:
                os.remove(file_path)
            except FileNotFoundError:
                pass

            group["files"] = [
                f for f in group["files"] if f["file_id"] != file_id
            ]
            save_group_db()
            return f"[INFO] Ficheiro {file_id} removido completamente do grupo {group_id}."

        elif user_id in file_found.get("encrypted_aes_key", {}):
            # Outro utilizador remove só acesso pessoal
            del file_found["encrypted_aes_key"][user_id]
            save_group_db()
            return f"[INFO] Acesso ao ficheiro {file_id} removido para {user_id}."

        return f"[ERRO] Utilizador {user_id} não tem acesso ao ficheiro {file_id}."

    return "[ERRO] ID de ficheiro inválido."

def handle_details(file_id):
    load_json_databases()

    # Ficheiro pessoal (FU)
    if file_id.startswith("FU"):
        for uid, udata in user_db.items():
            for f in udata.get("files", []):
                if f["file_id"] == file_id:
                    file_name = f.get("file", "desconhecido")
                    file_size = f.get("file_size", 0)
                    users = f.get("users", {})
                    return f"\nNome: {file_name}\nTamanho: {file_size} bytes\nPermissões: {users}"
        return f"[ERRO] Ficheiro {file_id} não encontrado."

    # Ficheiro de grupo (FG)
    elif file_id.startswith("FG"):
        for gid, group in group_db.items():
            for f in group.get("files", []):
                if f["file_id"] == file_id:
                    file_name = f.get("file", "desconhecido")
                    file_size = f.get("file_size", 0)
                    users = group.get("members", {})
                    return f"\nNome: {file_name}\nTamanho: {file_size} bytes\nUtilizadores: {users}"
        return f"[ERRO] Ficheiro {file_id} não encontrado em grupos."

    return "[ERRO] ID de ficheiro inválido."


def handle_replace(client_id, file_id):
    load_json_databases()

    # Verificar se o ficheiro é de um utilizador (FU) ou de um grupo (FG)
    if file_id.startswith("FU"):
        file_owner = None
        file_found = None

        # Procurar o ficheiro no cofre pessoal dos utilizadores
        for uid, udata in user_db.items():
            for f in udata.get("files", []):
                if f["file_id"] == file_id:
                    file_owner = uid
                    file_found = f
                    break
            if file_found:
                break

        if not file_found:
            return f"[ERRO] Ficheiro {file_id} não encontrado no cofre pessoal."

        # Verificar permissões do utilizador para o ficheiro
        if client_id != file_owner:
            if file_found["users"].get(client_id) not in ["W", "RW"]:
                return f"[ERRO] O utilizador '{client_id}' não tem permissões de escrita para o ficheiro {file_id}."

        # Se o ficheiro for encontrado, devolve as chaves públicas dos utilizadores com acesso
        user_public_keys = {}
        if "users" in file_found:
            for user, permission in file_found["users"].items():
                if user in user_db:
                    user_public_key_pem = user_db[user].get("public_key")
                    if user_public_key_pem:
                        user_public_keys[user] = user_public_key_pem

        return user_public_keys

    elif file_id.startswith("FG"):
        group_id = None
        file_found = None

        # Procurar o ficheiro entre os grupos
        for gid, group in group_db.items():
            for f in group.get("files", []):
                if f["file_id"] == file_id:
                    group_id = gid
                    file_found = f
                    break
            if file_found:
                break

        if not file_found:
            return f"[ERRO] Ficheiro {file_id} não encontrado no grupo."

        # Verificar permissões do utilizador
        group_info = group_db[group_id]
        if client_id not in group_info.get("members", {}) or group_info["members"].get(client_id) not in ["W", "RW"]:
            return f"[ERRO] O utilizador '{client_id}' não tem permissões de escrita para o ficheiro {file_id} no grupo '{group_id}'."

        # Se o ficheiro for encontrado, devolve as chaves públicas dos membros do grupo
        group_public_keys = {}
        for user, permission in group_info.get("members", {}).items():
            if user in user_db:
                user_public_key_pem = user_db[user].get("public_key")
                if user_public_key_pem:
                    group_public_keys[user] = user_public_key_pem

        return group_public_keys

    return f"[ERRO] ID de ficheiro inválido."


def handle_replace_finalize(file_id, file_content, encrypted_aes_keys, file_name, file_size):
    # Determinar se é ficheiro de grupo ou individual
    is_group_file = file_id.startswith("FG")
    db = group_db if is_group_file else user_db

    # Encontrar entrada apropriada
    file_entry_found = False
    for owner_id, owner_data in db.items():
        for file in owner_data["files"]:
            if file["file_id"] == file_id:
                file_entry_found = True
                file["file_size"] = file_size
                file["file"] = file_name
                file["encrypted_aes_key"] = encrypted_aes_keys
                vault_path = owner_data["vault_path"]
                break
        if file_entry_found:
            break

    if not file_entry_found:
        return {"status": "ERROR", "message": "Ficheiro não encontrado."}

    os.makedirs(vault_path, exist_ok=True)

    file_path = os.path.join(vault_path, file_id)
    with open(file_path, "wb") as f:
        f.write(base64.b64decode(file_content))

    # Guardar a base de dados atualizada
    if is_group_file:
        save_group_db()
    else:
        save_user_db()

    return {"status": "OK", "msg": "Ficheiro substituído com sucesso."}










