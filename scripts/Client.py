import asyncio
import os
import sys
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from ValidaCert import *
from MessageFormat import *

conn_port = 7777
max_msg_size = 99999

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

class Client:
    def __init__(self, sckt=None):
        self.sckt = sckt
        self.msg_cnt = 0
        self.share_cnt = 0
        self.shared_key = None
        self.client_name = None
        param_nums = dh.DHParameterNumbers(p,g, None)
        parameters = param_nums.parameters()
        self.DH_private_key = parameters.generate_private_key()
        self.DH_public_key = self.DH_private_key.public_key()
        self.cert_path = sys.argv[1] if len(sys.argv) > 1 else {print("Certificado não fornecido. Uso: python3 Client.py ../projCA/<client_name>.p12"), sys.exit(1)}
        try:
            self.private_key, self.client_cert, self.ca_cert = get_userdata(f"{self.cert_path}")
        except Exception as e:
            print(f"Erro ao carregar o certificado: {e}")
            sys.exit(1)
            
        
        
    def encrypt_message(self, plaintext):
        nonce = os.urandom(12) 
        aesgcm = AESGCM(self.shared_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_message(self, data):
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.shared_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_file_content(self, filepath, user_public_keys=None):
        """ Encripta o conteúdo do ficheiro e a chave AES com as chaves públicas fornecidas (para o share). """
        with open(filepath, "rb") as f:
            file_data = f.read()
            
        # Gerar uma chave AES para encriptar o ficheiro
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, file_data, None)

        encrypted_aes_keys = {}
        
        # Encriptar a chave AES com a chave pública de cada utilizador se fornecido
        if user_public_keys:
            for user, pub_key in user_public_keys.items():
                encrypted_aes_key = pub_key.encrypt(
                    aes_key,
                    padding.PKCS1v15() 
                )
                encrypted_aes_keys[user] = base64.b64encode(encrypted_aes_key).decode()  # Codificar a chave AES encriptada em base64

        # Retorna o conteúdo encriptado, a chave AES encriptada e as chaves AES encriptadas para os utilizadores
        return base64.b64encode(nonce + ciphertext).decode(), encrypted_aes_keys
    
    def decrypt_file_content(self, file_content, encrypted_aes_key, private_key):
        """ Desencripta o conteúdo do ficheiro usando a chave AES e a chave privada. """
        try:
            # Primeiro, separar o nonce (12 bytes) do ciphertext
            nonce = file_content[:12]  # Extrai os primeiros 12 bytes como nonce
            ciphertext = file_content[12:]  # O restante é o ciphertext

            # Desencriptar a chave AES usando a chave privada do cliente
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.PKCS1v15()
            )

            # Usar a chave AES para desencriptar o conteúdo
            aesgcm = AESGCM(aes_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_data

        except Exception as e:
            print(f"Erro ao desencriptar o conteúdo: {e}")
            return None
        
    def encrypt_aes_key_for_users(self, aes_key, public_keys_dict):
        encrypted_keys = {}

        for user, public_key_b64 in public_keys_dict.items():
            try:
                # Decode da chave pública em base64
                pem_bytes = base64.b64decode(public_key_b64)
                public_key = serialization.load_pem_public_key(pem_bytes)

                # Encriptação da chave AES com a chave pública do utilizador
                encrypted_key = public_key.encrypt(
                    aes_key,
                    padding.PKCS1v15()
                )

                encrypted_keys[user] = base64.b64encode(encrypted_key).decode()
            except Exception as e:
                print(f"[ERRO] Não foi possível encriptar chave para {user}: {e}")

        return encrypted_keys





    def process(self, msg=b""):
        """ Processa uma mensagem recebida do SERVIDOR. """
        self.msg_cnt += 1

        if self.msg_cnt == 1:
            # Envia a chave pública Diffie-Hellman (g^a)
            client_pub_key_bytes = self.DH_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return client_pub_key_bytes

        elif self.msg_cnt == 2:
            # Recebe (g^b, assinatura), certificado do servidor
            rest, server_cert_bytes = unpair(msg)
            server_pub_key_bytes, server_signature = unpair(rest)

            server_pub_key = serialization.load_pem_public_key(server_pub_key_bytes)
            server_cert = x509.load_pem_x509_certificate(server_cert_bytes)

            client_pub_key_bytes = self.DH_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            client_cert_bytes = self.client_cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
            client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
            subject = client_cert.subject
            self.client_name = subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value

            if not valida_cert(server_cert, server_cert.subject, self.ca_cert):
                return ValueError("Certificado do Servidor inválido!")
            else:
                self.shared_key = self.DH_private_key.exchange(server_pub_key)
                self.shared_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'sts key',
                ).derive(self.shared_key)

                try:
                    server_cert.public_key().verify(
                        server_signature,
                        mkpair(server_pub_key_bytes, client_pub_key_bytes),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                except Exception as e:
                    print(f"Erro na verificação da assinatura do servidor: {e}")
                    return ValueError("Falha na verificação da assinatura do servidor!")

                # Preparar assinatura do cliente
                signature = self.private_key.sign(
                    mkpair(client_pub_key_bytes, server_pub_key_bytes),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                client_cert_bytes = self.client_cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                )

                return mkpair(
                    mkpair(client_pub_key_bytes, signature),
                    client_cert_bytes
                )

            
        elif self.msg_cnt >= 3:
            try:
                decrypted = self.decrypt_message(msg).decode()
                response_data = None
                
                if self.msg_cnt > 3:
                    try:
                        response_data = json.loads(decrypted)
                        print(f"Resposta: {response_data.get('msg', '')}")
                    except json.JSONDecodeError:
                        print(f'Resposta: {decrypted}')
                        pass

            except Exception as e:
                print("Erro ao desencriptar mensagem:", e)
                return None
            
            #==========READ -FINAL ANSWER=================
            if (response_data):
                if response_data.get("action") == "read_reply":
                    file_content = base64.b64decode(response_data["file_content"])
                    file_id = response_data["file_id"]
                    aes_key = base64.b64decode(response_data["aes_key"])
                    decrypted_file = self.decrypt_file_content(file_content, aes_key, self.private_key)
                    
                    
                    if decrypted_file:
                        # Exibir o conteúdo do ficheiro desencriptado
                        print(f"Conteúdo do ficheiro {file_id}:")
                        print(decrypted_file.decode())  # Supondo que o conteúdo seja texto e decodificável para UTF-8
                    else:
                        print("[ERRO] Falha ao desencriptar o conteúdo do ficheiro.")
                        
                #==========SHARE -FINAL ANSWER=================            
                if (response_data and response_data.get("action") == "share"):
                    try:
                        decrypted = self.decrypt_message(msg).decode()
                        share_data = json.loads(decrypted)

                        # Extrair os dados
                        encrypted_aes_key = base64.b64decode(share_data["encrypted_aes_key"])
                        target_public_key = share_data["public_key"]
                        
                        print(f"Chave pública do target_user: {target_public_key}")

                        # Desencriptar AES com a chave privada do cliente
                        aes_key = self.private_key.decrypt(
                            encrypted_aes_key,
                            padding.PKCS1v15()
                        )
                        target_public_key_pem = base64.b64decode(share_data["public_key"])
                        target_public_key = serialization.load_pem_public_key(target_public_key_pem)        

                        try:
                            encrypted_aes_key = target_public_key.encrypt(
                                aes_key,
                                padding.PKCS1v15() 
                            )
                        except Exception as e: 
                            print("Erro ao carregar a chave pública do target_user:", e)
                            return None

                        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()
                        # Enviar nova chave AES encriptada para o servidor associada ao ficheiro e target_user
                        msg = {
                            "requester": self.client_name,
                            "file_id": share_data["file_id"],
                            "target_user": share_data["target_user"],
                            "action": "share_finalize",
                            "encrypted_key": encrypted_aes_key_b64
                        }
                        msg = self.encrypt_message(json.dumps(msg).encode())
                        self.share_cnt = 0
                        return msg
                    except Exception as e:
                        print("Erro ao desencriptar chave:", e)
                        return None
                    
                    
                #==========GROUP ADD-USER FINALIZE=================
                if (response_data and response_data.get("action") == "group add-user finalize"):
                    try:
                        decrypted = self.decrypt_message(msg).decode()
                        group_data = json.loads(decrypted)

                        encrypted_aes_keys_dict = group_data["encrypted_aes_keys"]  # <- Dicionário com as chaves AES encriptadas por ficheiro
                        target_public_key_b64 = group_data["public_key"]  # Chave pública do utilizador a ser adicionado ao grupo

                        # Cria um dicionário para armazenar as chaves AES reencriptadas por ficheiro
                        encrypted_aes_keys_new_b64_dict = {}

                        # Itera sobre cada ficheiro do grupo
                        for file_id, encrypted_aes_key_b64 in encrypted_aes_keys_dict.items():
                            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

                            # Desencripta a chave AES com a chave privada do cliente
                            try:
                                aes_key = self.private_key.decrypt(
                                    encrypted_aes_key,
                                    padding.PKCS1v15()
                                )
                            except Exception as e:
                                print(f"[ERRO] Não foi possível desencriptar a chave AES para o ficheiro {file_id}: {e}")
                                continue  # Se falhar para um ficheiro, continua para o próximo

                            # Carrega a chave pública do utilizador a ser adicionado (target_user)
                            target_public_key_pem = base64.b64decode(target_public_key_b64)
                            target_public_key = serialization.load_pem_public_key(target_public_key_pem)

                            # Reencripta a chave AES com a chave pública do target_user
                            try:
                                encrypted_aes_key_new = target_public_key.encrypt(
                                    aes_key,
                                    padding.PKCS1v15()
                                )
                                encrypted_aes_key_new_b64 = base64.b64encode(encrypted_aes_key_new).decode()
                                encrypted_aes_keys_new_b64_dict[file_id] = encrypted_aes_key_new_b64
                            except Exception as e:
                                print(f"[ERRO] Não foi possível reencriptar a chave AES para o ficheiro {file_id}: {e}")
                                continue  # Se falhar para um ficheiro, continua para o próximo

                        # Prepara a mensagem de confirmação com as chaves AES reencriptadas por ficheiro
                        msg = {
                            "requester":self.client_name,
                            "group_id": group_data["group_id"],
                            "target_user": group_data["user"],
                            "action": "group add-user confirm",
                            "encrypted_keys": encrypted_aes_keys_new_b64_dict  # Dicionário com as chaves AES reencriptadas por ficheiro
                        }

                        msg = self.encrypt_message(json.dumps(msg).encode())
                        return msg

                    except Exception as e:
                        print("Erro ao processar group add-user finalize:", e)
                        return None
                    
                #==========GROUP ADD - FINAL ANSWER==========
                if(response_data and response_data.get("action") == "add file to group vault"):
                    public_keys = response_data.get("public_keys")
                    aes_key = response_data.get("aes_key")
                    group_id = response_data.get("group_id")
                    file_id = response_data.get("file_id")
                    aes_key = self.private_key.decrypt(
                        base64.b64decode(aes_key),
                        padding.PKCS1v15()
                    )
                    encrypted_aes_keys = {}
                    encrypted_aes_keys = self.encrypt_aes_key_for_users(aes_key, public_keys)
                    result = make_groupAdd_client_reply(aes_keys=encrypted_aes_keys, group_id=group_id, file_id=file_id)
                    return self.encrypt_message(json.dumps(result).encode())
                    
                    
                #==========REPLACE -FINAL ANSWER================= 
                if(response_data and response_data.get("action") == "replace"):
                    file_path = response_data["file_path"]
                    print(f"Ficheiro a ser substituído: {file_path}")
                    file_id = response_data["file"]
                    user_public_keys = response_data["msg"]
                    try:
                        if user_public_keys:
                                    # Para cada chave pública fornecida
                                    for user, pub_key_str in user_public_keys.items():
                                        try:
                                            # Remove espaços extras e certifica que a chave está em formato PEM
                                            pub_key_str = pub_key_str.strip()

                                            # Carregar a chave pública PEM
                                            pub_key = serialization.load_pem_public_key(
                                                pub_key_str.encode(),  # Converte a string em bytes antes de carregar
                                                backend=default_backend()
                                            )
                                            
                                            # Substituir a chave pública no dicionário pela chave carregada
                                            user_public_keys[user] = pub_key

                                        except Exception as e:
                                            print(f"[ERRO] A chave pública do utilizador {user} não está no formato correto ou é inválida: {e}")
                                            continue  # Ignora esta chave pública e passa para o próximo utilizador
                        encrypted_file_content, encrypted_aes_keys = self.encrypt_file_content(file_path, user_public_keys)

                        # Prepara a mensagem a ser enviada para o servidor com a informação do ficheiro encriptado
                        msg = {
                            "action": "replace-finalize",
                            "file_id": file_id,
                            "file_name": os.path.basename(file_path),
                            "file_size": os.path.getsize(file_path),
                            "encrypted_file_content": encrypted_file_content,
                            "encrypted_aes_keys": encrypted_aes_keys  # Chaves AES encriptadas para cada utilizador
                        }

                        # Envia a mensagem encriptada para o servidor
                        encrypted_msg = self.encrypt_message(json.dumps(msg).encode())
                        return encrypted_msg

                    except Exception as e:
                        print(f"[ERRO] Falha ao processar o ficheiro {file_id}: {e}")
                        return None

                pass

            #==========INPUT=================
            user_input = input(">> ")
            if user_input.strip().lower() == "exit":
                exit_msg = make_exit_msg(user=self.client_name, msg="A sair...")
                return self.encrypt_message(json.dumps(exit_msg).encode())
            
            #==========ADD=================
            elif user_input.strip().lower().startswith("add"):
                filepath = user_input[4:].strip()
                if not os.path.exists(filepath):
                    print(f"[ERRO] O ficheiro '{filepath}' não existe.")
                else:
                    try:
                        # Encripta ficheiro e chave
                        client_name = self.client_name
                        encrypted_file_b64, encrypted_aes_key = self.encrypt_file_content(filepath, user_public_keys={client_name: self.client_cert.public_key()})
                        users_permissions = {self.client_name: "RW"}
                        add_msg = make_add_msg(
                            file_name = os.path.basename(filepath),
                            file_size = os.path.getsize(filepath),
                            file_content = encrypted_file_b64,
                            encrypted_aes_key= encrypted_aes_key,
                            users = users_permissions,
                            msg = "Upload de ficheiro encriptado"
                        )

                        return self.encrypt_message(json.dumps(add_msg).encode())

                    except Exception as e:
                        print(f"[ERRO] Falha ao ler ficheiro: {e}")
                
            #==========LIST=================
            elif user_input.strip().lower().startswith("list"):
                parts = user_input.strip().split()
                target_type = None
                target_id = None

                if len(parts) == 1:
                    # Apenas "list" — lista tudo para o próprio user
                    target_type = "user"
                    target_id = self.client_name
                elif len(parts) == 3 and parts[1] in ["-u", "-g"]:
                    if parts[1] == "-u":
                        target_type = "user"
                        target_id = parts[2]
                    elif parts[1] == "-g":
                        target_type = "group"
                        target_id = parts[2]
                    else:
                        print("[ERRO] Argumento inválido. Usa -u <user-id> ou -g <group-id>.")
                        return None
                else:
                    print("[ERRO] Uso: list [-u user-id | -g group-id]")
                    return None

                list_msg = make_list_msg(
                    requester=self.client_name,
                    target_type=target_type,
                    target_id=target_id,
                    msg=f"Pedido de listagem de ficheiros de {target_type} '{target_id}'"
                )
                return self.encrypt_message(json.dumps(list_msg).encode())
            
            
            #==========SHARE=================
            elif user_input.strip().lower().startswith("share"):
                parts = user_input.strip().split()
                if len(parts) != 4:
                    print("[ERRO] Uso: share <file-id> <user-id> <permission>")
                    return None

                _, file_id, user_id, permission = parts

                if permission not in ["R", "W", "RW"]:
                    print("[ERRO] Permissão inválida. Usa 'R' para leitura ou 'W' para escrita.")
                    return None

                share_msg = make_share_msg(
                    permission=permission,
                    file_id=file_id,
                    user=user_id,
                    requester=self.client_name,
                )
                self.share_cnt += 1
                return self.encrypt_message(json.dumps(share_msg).encode())
            
            #==========READ=================
            elif user_input.strip().lower().startswith("read"):
                parts = user_input.strip().split()
                if len(parts) != 2:
                    print("[ERRO] Uso: read <file-id>")
                    return None

                _, file_id = parts
                read_msg = make_read_msg(
                    file_id=file_id,
                    requester=self.client_name,
                )
                return self.encrypt_message(json.dumps(read_msg).encode())
            
            
            #==========REVOKE=================
            elif user_input.strip().lower().startswith("revoke"):
                parts = user_input.strip().split()
                if len(parts) != 3:
                    print("[ERRO] Uso: revoke <file-id> <user-id>")
                    return None

                _, file_id, user_id = parts
                revoke_msg = make_revoke_msg(
                    file_id=file_id,
                    user=user_id,
                )
                return self.encrypt_message(json.dumps(revoke_msg).encode())
                
            #==========GROUP CREATE=================
            elif user_input.strip().lower().startswith("group create"):
                parts = user_input.strip().split()
                if len(parts) != 3:
                    print("[ERRO] Uso: group create <group-name>")
                    return None

                _, _, group_id = parts
                group_create_msg = make_groupCreate_msg(
                    group_name=group_id,
                )
                return self.encrypt_message(json.dumps(group_create_msg).encode())
            
            #==========GROUP DELETE-USER=================
            elif user_input.strip().lower().startswith("group delete-user"):
                parts = user_input.strip().split()
                if len(parts) != 4:
                    print("[ERRO] Uso: group delete-user <group-id> <user-id>")
                    pass
                _, _, group_id, user_id = parts
                group_delete_user_msg = make_groupDeleteUser_msg(group_id=group_id, user=user_id)
                return self.encrypt_message(json.dumps(group_delete_user_msg).encode())

            #==========GROUP DELETE=================
            elif user_input.strip().lower().startswith("group delete"):
                parts = user_input.strip().split()
                if len(parts) != 3:
                    print("[ERRO] Uso: group delete <group-id>")
                    return None

                _, _, group_id = parts
                group_delete_msg = make_groupDelete_msg(
                    group_id=group_id,
                )
                return self.encrypt_message(json.dumps(group_delete_msg).encode())
            
            
            #==========GROUP ADD-USER=================
            elif user_input.strip().lower().startswith("group add-user"):
                parts = user_input.strip().split()
                if len(parts) != 5:
                    print("[ERRO] Uso: group add-user <group-id> <user-id> <permissions>")
                    return None

                _, _, group_id, user_id, permissions = parts
                group_add_user_msg = make_groupAddUser_msg(
                    permissions=permissions,
                    group_id=group_id,
                    user=user_id,
                    owner=self.client_name,
                )
                return self.encrypt_message(json.dumps(group_add_user_msg).encode())
                
            #==========GROUP LIST=================
            elif user_input.strip().lower().startswith("group list"):
                group_list_msg = make_groupList_msg()
                return self.encrypt_message(json.dumps(group_list_msg).encode())
            
            #==========GROUP ADD=================
            elif user_input.strip().lower().startswith("group add"):
                parts = user_input.strip().split()
                if len(parts) != 4:
                    print("[ERRO] Uso: group add <group-id> <file-path>")
                    return None

                _, _, group_id, filepath = parts
                if not os.path.exists(filepath):
                    print(f"[ERRO] O ficheiro '{filepath}' não existe.")
                else:
                    try:
                        # Encripta ficheiro e chave
                        client_name = self.client_name
                        encrypted_file_b64, encrypted_aes_key = self.encrypt_file_content(filepath, user_public_keys={client_name: self.client_cert.public_key()})
                        add_msg = make_groupAdd_msg(
                            file = os.path.basename(filepath),
                            file_size = os.path.getsize(filepath),
                            file_content = encrypted_file_b64,
                            encrypted_key= encrypted_aes_key,
                            group_id = group_id
                        )

                        return self.encrypt_message(json.dumps(add_msg).encode())

                    except Exception as e:
                        print(f"[ERRO] Falha ao ler ficheiro: {e}")
                        
            #==========DELETE=================
            elif user_input.strip().lower().startswith("delete"):
                parts = user_input.strip().split()
                if len(parts) != 2:
                    print("[ERRO] Uso: delete <file-id>")
                    return None

                _, file_id = parts
                delete_msg = make_delete_msg(
                    file=file_id,
                    user=self.client_name,
                )
                return self.encrypt_message(json.dumps(delete_msg).encode())
            
            #==========DETAILS=================
            elif user_input.strip().lower().startswith("details"):
                parts = user_input.strip().split()
                if len(parts) != 2:
                    print("[ERRO] Uso: details <file-id>")
                    return None

                _, file_id = parts
                details_msg = make_details_msg(
                    file_id=file_id,
                )
                return self.encrypt_message(json.dumps(details_msg).encode())
            
            #==========REPLACE=================
            elif user_input.strip().lower().startswith("replace"):
                parts = user_input.strip().split()
                if len(parts) != 3:
                    print("[ERRO] Uso: replace <file-id> <file-path>")
                    return None

                _, file_id, filepath = parts
                if not os.path.exists(filepath):
                    print(f"[ERRO] O ficheiro '{filepath}' não existe.")
                else:
                    replace_msg = make_replace_msg(
                        file=file_id,
                        file_path=filepath,
                    )

                    return self.encrypt_message(json.dumps(replace_msg).encode())
            
            if len(user_input.strip()) == 0:
                return None

        return self.encrypt_message(user_input.encode())

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
