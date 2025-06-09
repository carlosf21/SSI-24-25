import json
import base64

user = {
    "CN": "User X (SSI Vault Client X)",
    "PSEUDONYM": "user_x",
    "VAULT_PATH": "/path/to/vault",
    "GROUPS": ["Group X", "Group Y"],
    "VAULT": {
        "files": ['file1', 'file2', '...'],
    },
    "PUBLIC_KEY" : "public_key_example",
}

group = {
    "VAULT_PATH": "/path/to/group/vault",
    "GROUP_ID": "GXXXX",
    "NAME": "Group X",
    "ADMIN": "user_x",
    "MEMBERS": ["user_x", "user_y"],
    "VAULT": {
        "files": ['file1', 'file2', '...'],
    },
}

file = {
    "owner": "user_x",
    "file_id": "FXXXX",
    "file_name": "file.txt",
    "file_size": 123,
    "filecontent": base64.b64encode(b"content example").decode(),
    "permissions": {
        "shared_users": [],
        "shared_groups": []
    },
}