import os

FILE_ID_COUNTER_PATH = "../Database/used_ids/file_id_counter.txt"
GROUP_FILE_ID_COUNTER_PATH = "../Database/used_ids/group_file_id_counter.txt"
USER_ID_COUNTER_PATH = "../Database/used_ids/user_id_counter.txt"
GROUP_ID_COUNTER_PATH = "../Database/used_ids/group_id_counter.txt"

def generate_user_file_id():

    if not os.path.exists(FILE_ID_COUNTER_PATH):
        with open(FILE_ID_COUNTER_PATH, "w") as f:
            f.write("0")

    with open(FILE_ID_COUNTER_PATH, "r") as f:
        current = int(f.read().strip())

    new_id_number = current + 1

    with open(FILE_ID_COUNTER_PATH, "w") as f:
        f.write(str(new_id_number))

    return f"FU{new_id_number:09d}"

def generate_group_file_id():

    if not os.path.exists(GROUP_FILE_ID_COUNTER_PATH):
        with open(GROUP_FILE_ID_COUNTER_PATH, "w") as f:
            f.write("0")

    with open(GROUP_FILE_ID_COUNTER_PATH, "r") as f:
        current = int(f.read().strip())

    new_id_number = current + 1

    with open(GROUP_FILE_ID_COUNTER_PATH, "w") as f:
        f.write(str(new_id_number))

    return f"FG{new_id_number:09d}"

def generate_group_id():
    if not os.path.exists(GROUP_ID_COUNTER_PATH):
        with open(GROUP_ID_COUNTER_PATH, "w") as f:
            f.write("0")

    with open(GROUP_ID_COUNTER_PATH, "r") as f:
        current = int(f.read().strip())

    new_id_number = current + 1

    with open(GROUP_ID_COUNTER_PATH, "w") as f:
        f.write(str(new_id_number))

    return f"G{new_id_number:05d}"