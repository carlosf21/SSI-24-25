import asyncio
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from ValidaCert import *
from ClientHandler import *
from DatabaseHandler import *
from Logger import log_message, log_warning, log_error, log_critical, log_debug, log_exception
import traceback
from IdGenerator import generate_user_file_id, generate_group_file_id


conn_cnt = 0
conn_port = 7777
max_msg_size = 99999

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

class ServerWorker(object):
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.client_id = None
        
        param_nums = dh.DHParameterNumbers(p,g, None)
        parameters = param_nums.parameters()
        self.DH_private_key = parameters.generate_private_key()
        self.DH_public_key = self.DH_private_key.public_key()
        self.cli_pub_key = None
        self.shared_key = None
        self.client_cert = None

        self.private_key, self.server_cert, self.ca_cert = get_userdata("../projCA/VAULT_SERVER.p12")
        
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


    def process(self, msg):
        """ Processa a mensagem enviada pelo CLIENTE. """
        self.msg_cnt += 1
    

        if self.msg_cnt == 1:
            # Recebe a chave pública DH do cliente
            client_pub_key_bytes = msg

            client_pub_key = serialization.load_pem_public_key(client_pub_key_bytes)

            self.shared_key = self.DH_private_key.exchange(client_pub_key)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'sts key',
            ).derive(self.shared_key)

            server_pub_key_bytes = self.DH_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            server_cert_bytes = self.server_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            )

            server_signature = self.private_key.sign(
                mkpair(server_pub_key_bytes, client_pub_key_bytes),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return mkpair(mkpair(server_pub_key_bytes, server_signature), server_cert_bytes)

        elif self.msg_cnt == 2:
            try:
                # Recebe ((client_pub_key_bytes, signature), client_cert_bytes)
                inner_pair, client_cert_bytes = unpair(msg)
                client_pub_key_bytes, signature = unpair(inner_pair)

                client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
                subject = client_cert.subject
                client_id = subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value
                self.client_id = client_id

                if not valida_cert(client_cert, subject, self.ca_cert):
                    log_critical(f"[{client_id}] Certificado do Cliente inválido!")
                    return ValueError("Certificado do Cliente inválido!")

                server_pub_key_bytes = self.DH_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                client_cert.public_key().verify(
                    signature,
                    mkpair(client_pub_key_bytes, server_pub_key_bytes),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                print(f"[{client_id}] Cliente autenticado com sucesso!")

                cli_public_key_pem = client_cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()

                register_user_if_needed(client_id, cli_public_key_pem)
                result = make_read_reply()
                log_message("SENT", result)
                return self.encrypt_message(json.dumps(result).encode())

            except Exception as e:
                log_critical(f"[{self.client_id}] Erro na verificação da assinatura: {e}")
                return None
            
            

        elif self.msg_cnt > 2:
            try:
                plaintext = self.decrypt_message(msg)
                txt = plaintext.decode()
                print(f'[{self.client_id}] : {txt}')

                try:
                    msg_dict = json.loads(txt)
                    log_message("RECEIVED", txt)
                    response_dict = client_handler(msg_dict, self.client_id)

                    if response_dict.get("action") == "ready":
                        print(f"Cliente {self.client_id} está pronto.")
                        log_message("SENT", response_dict)
                        return self.encrypt_message(response_dict.get("msg").encode())
                    
                    #======== ADD ========
                    elif response_dict.get("action") == "add":
                        file_id = generate_user_file_id()
                        file_path = os.path.join(USER_VAULTS_DIR, self.client_id, file_id)
                        if not os.path.exists(os.path.dirname(file_path)):
                            os.makedirs(os.path.dirname(file_path))
                        try:
                            with open(file_path, "wb") as f:
                                f.write(base64.b64decode(msg_dict["file_content"]))
                        except Exception as e:
                            log_exception(f"[{self.client_id}] Erro ao escrever o ficheiro: {e}")
                            print(f"[{self.client_id}] Erro ao escrever o ficheiro: {e}")
                            return self.encrypt_message(b"Erro ao escrever o ficheiro.")
                        response_dict["file_id"] = file_id
                        file_id = handle_add(self.client_id, msg_dict)
                        log_message("SENT", response_dict)
                        return self.encrypt_message(file_id.encode())
                    
                    #======== LIST ========
                    elif response_dict.get("action") == "list":
                        result = handle_list(response_dict, USER_JSON_DIR, GROUP_JSON_DIR)
                        log_message("SENT", response_dict)
                        return self.encrypt_message(result)


                    #======== SHARE ========
                    elif response_dict.get("action") == "share":
                        try:
                            file_id = msg_dict.get("file_id")
                            target_user = msg_dict.get("user")
                            permission = msg_dict.get("permission")
                            
                            result = handle_share(self.client_id, file_id, target_user, permission)
                            if isinstance(result, str) and result.startswith("[ERRO]"):
                                    return self.encrypt_message(result.encode())

                            pub_key_target, aes_key = result

                            response = {
                                    "action": "share",
                                    "file_id": file_id,
                                    "requester": self.client_id,
                                    "target_user": target_user,
                                    "encrypted_aes_key": base64.b64encode(aes_key).decode(),
                                    "public_key":pub_key_target
                                }
                            log_message("SENT", response)
                            return self.encrypt_message(json.dumps(response).encode())
                            
                        except Exception as e:
                            log_exception(f"[{self.client_id}] Erro ao partilhar o ficheiro: {e}")
                            print(f"[{self.client_id}] Erro ao partilhar o ficheiro: {e}")
                            return self.encrypt_message(b"Erro ao partilhar o ficheiro.")
                    
                    elif response_dict.get("action") == "share_finalize":
                        file_id = msg_dict.get("file_id")
                        target_user = msg_dict.get('target_user')
                        encrypted_key_b64 = msg_dict.get("encrypted_key")
                        requester = msg_dict.get("requester")

                        load_json_databases()

                        try:
                            result = finalize_share(requester, file_id, target_user, encrypted_key_b64)
                            log_message("SENT", result)
                            return self.encrypt_message(result.encode())
                        except FileNotFoundError:
                            log_exception(f"[{self.client_id}] Erro ao finalizar a partilha: Ficheiro não encontrado.")
                            print(f"[{self.client_id}] Erro ao atualizar a chave AES: Ficheiro não encontrado.")
                            return self.encrypt_message(b"[ERRO] Ficheiro nao encontrado ou erro ao atualizar a chave AES.")

                    
                    
                    #======== DELETE ========
                    elif response_dict.get("action") == "delete":
                        file_id = msg_dict.get("file")

                        try:
                            result = handle_delete(file_id, self.client_id)
                        except FileNotFoundError:
                            log_exception(f"[{self.client_id}] Erro ao eliminar o ficheiro: Ficheiro não encontrado.")
                            print(f"[{self.client_id}] Erro ao eliminar o ficheiro: Ficheiro não encontrado.")
                            return self.encrypt_message(b"Erro ao eliminar o ficheiro.")
                        
                        result = make_delete_reply(msg=result)

                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    #======== READ ========
                    elif response_dict.get("action") == "read":
                        file_id = msg_dict.get("file_id")
                        requester = msg_dict.get("requester")

                        try:
                            file_content_b64, aes_key_b64 = handle_read(requester, file_id)
                        except:
                            log_error(f"[{self.client_id}] Erro ao ler o ficheiro")
                            result = f"Erro ao ler o ficheiro"
                            return self.encrypt_message(result.encode())
                        
                        result = {
                            "action": "read_reply",
                            "file_id": file_id,
                            "file_content": base64.b64decode(file_content_b64).decode(),
                            "aes_key": base64.b64decode(aes_key_b64).decode()
                        }

                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())


                    #======== REVOKE ========
                    elif response_dict.get("action") == "revoke":
                        file_id = msg_dict.get("file_id")
                        target_user = msg_dict.get("user")
                        requester = self.client_id

                        try:
                            result = handle_revoke(requester, file_id, target_user)
                            msg = make_revoke_reply()
                            log_message("SENT", msg)
                            return self.encrypt_message(json.dumps(msg).encode())
                        except Exception:
                            log_exception(f"[{self.client_id}] Erro ao revogar o ficheiro:")
                            return self.encrypt_message(b"Erro ao revogar o ficheiro.")
                    
                    #======== GROUP CREATE ========
                    elif response_dict.get("action") == "create group":
                        group_name = msg_dict.get("group_name")
                        result = handle_group_create(self.client_id, group_name)
                        result = make_groupCreate_reply(result)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    #======== GROUP DELETE ========
                    elif response_dict.get("action") == "delete group":
                        group_name = msg_dict.get("group_name")
                        result = handle_group_delete(self.client_id, group_name)
                        result = make_groupDelete_reply(msg=result)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    
                    #==========GROUP ADD-USER=================
                    elif response_dict.get("action") == "add user to group":
                        group_name = msg_dict.get("group_id")
                        user_to_add = msg_dict.get("user")
                        permissions = msg_dict.get("permissions")
                        result = handle_group_add_user(self.client_id, group_name, user_to_add, permissions)
                        if isinstance(result, str):
                            print(result)
                            return self.encrypt_message(result.encode())
                        else:
                            target_public_key, aes_keys = result
                            result = {
                                "action": "group add-user finalize",
                                "group_id": group_name,
                                "user": user_to_add,
                                "requester": self.client_id,
                                "encrypted_aes_keys": aes_keys,
                                "public_key": target_public_key
                            }
                            log_message("SENT", result)
                            return self.encrypt_message(json.dumps(result).encode())
                    
                    
                    #==========GROUP ADD-USER FINALIZE=================
                    elif response_dict.get("action") == "group add-user confirm":
                        group_id = msg_dict.get("group_id")
                        requester = msg_dict.get("requester")
                        encrypted_keys_b64 = msg_dict.get("encrypted_keys")
                        target_user = msg_dict.get("target_user")

                        load_json_databases()


                        result = finalize_group_add_user(requester, group_id, target_user, encrypted_keys_b64)
                        result = make_groupAddUser_reply(msg=result)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                        
                    
                    #==========GROUP DELETE-USER=================
                    elif response_dict.get("action") == "remove user from group":
                        group_id = msg_dict.get("group_id")
                        user_id = msg_dict.get("user")
                        result = handle_group_remove_user(self.client_id, group_id, user_id)
                        result = make_groupDelete_reply(msg=result)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    #==========GROUP LIST=================
                    elif response_dict.get("action") == "group list":
                        result = handle_group_list(self.client_id)
                        result = make_groupList_reply(msg=result)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    #==========GROUP ADD=================
                    elif response_dict.get("action") == "add file to group vault":
                        group_id = msg_dict.get("group_id")
                        file_id = generate_group_file_id()
                        result = handle_group_add(self.client_id, msg_dict, file_id)
                        if isinstance(result, str):
                            return self.encrypt_message(result.encode())
                        public_keys, aes_key = result
                        result = make_groupAdd_first_reply(public_keys=public_keys, aes_key=aes_key, group_id=group_id, file_id=file_id)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    elif response_dict.get("action") == "add file to group vault reply":
                        group_id = msg_dict.get("group_id")
                        file_id = msg_dict.get("file_id")
                        encrypted_aes_keys = msg_dict.get("aes_keys")
                        result = handle_group_add_finalize(group_id, file_id, encrypted_aes_keys)
                        result = make_groupAdd_reply(msg=result)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    
                    #==========DETAILS=================
                    elif response_dict.get("action") == "details":
                        file_id = msg_dict.get("file_id")
                        result = handle_details(file_id)
                        result = make_details_reply(msg=result)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())


                    #==========REPLACE=================
                    elif response_dict.get("action") == "replace":
                        file_id = msg_dict.get("file")
                        file_path = msg_dict.get("file_path")
                        result = handle_replace(self.client_id, file_id)
                        if isinstance(result, str):
                            return self.encrypt_message(result.encode())
                        result = make_replace_reply(msg=result, file_path=file_path, file=file_id)
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    elif response_dict.get("action") == "replace-finalize":
                        file_id = msg_dict.get("file_id")
                        file_content = msg_dict.get("encrypted_file_content")
                        encrypted_aes_keys = msg_dict.get("encrypted_aes_keys")
                        file_name = msg_dict.get("file_name")
                        file_size = msg_dict.get("file_size")
                        result = handle_replace_finalize(file_id, file_content, encrypted_aes_keys, file_name, file_size)
                        if isinstance(result, str):
                            return self.encrypt_message(result.encode())
                        log_message("SENT", result)
                        return self.encrypt_message(json.dumps(result).encode())
                    
                    #==========EXIT=================
                    elif response_dict.get("action") == "exit":
                        log_message("SENT", response_dict)
                        print(f"[{self.client_id}] Cliente terminou sessão.")
                        return None

                except json.JSONDecodeError:
                    log_debug("RECEIVED", txt)
                    log_warning(f"[{self.client_id}] Mensagem não era JSON válida.")
                    print(f"[{self.id}] Mensagem não era JSON válida.")
                    return self.encrypt_message(b"Mensagem invalida")

            except Exception as e:
                log_error(f"[{self.client_id}] Erro ao desencriptar/processar: {e}")
                print(f"[{self.id}] Erro ao desencriptar/processar: {e}")
                return None


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    create_vault_dirs()
    ensure_database_files()
    load_json_databases()

    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()
