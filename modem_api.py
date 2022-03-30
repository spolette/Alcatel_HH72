import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import json

def encryptAdmin(value):
    # Hardcoded key for encryption
    KEY = "e5dl12XYVggihggafXWf0f2YSf2Xngd1"
    encoded = bytearray()
    for index, char in enumerate(value):
        valueCode = ord(char)
        keyCode = ord(KEY[index % len(KEY)])
        encoded.append((240 & keyCode) | ((15 & valueCode) ^ (15 & keyCode)))
        encoded.append((240 & keyCode) | ((valueCode >> 4) ^ (15 & keyCode)))

    return encoded.decode()

def encryptToken(token, param0, param1):
    # First, encode token using custom algorithm
    encodedToken = encryptAdmin(token).encode()

    # Then, cipher using AES/CBC/PKCS7Padding 
    key = param0.encode()   # Convert string to bytearray
    iv = param1.encode()    # Convert string to bytearray

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Do padding
    padder = padding.PKCS7(128).padder()
    input = padder.update(encodedToken) + padder.finalize()

    # Encrypt padded data
    ct = encryptor.update(input) + encryptor.finalize()

    # base64 encode
    encoded = b64encode(ct).decode()

    return encoded

class ModemAPI:
    def __init__(self, url: str) -> None:
        self._url = url
        self._password = None
        self.session = requests.Session()
        self.session.headers = {
            "_TclRequestVerificationKey": "KSDHSDFOGQ5WERYTUIQWERTYUISDFG1HJZXCVCXBN2GDSMNDHKVKFsVBNf",
            "Referer": f"{url}"
        }
        self._token = None
        self._restoreToken()
    
    def setPassword(self, password: str) -> None:
        self._password = password

    def _saveToken(self):
        with open("session", "w") as session:
            session.writelines([self._token])

    def _restoreToken(self):
        token = None

        try:
            with open("session", "r") as session:
                token = session.readlines()[0]
        except:
            pass
        
        self._token = token

    def _getLoginState(self) -> bool:
        result = self._runCommand("GetLoginState")
        loggedIn = result["State"] == 1

        if loggedIn:
            if self._token is None:
                # We are supposed to be logged in, but we don't have the token
                return False
            else:
                # Update headers with token
                self.session.headers["_TclRequestVerificationToken"] = self._token

        return loggedIn

    def _login(self):
        result = self._runCommand(
            "Login", UserName=encryptAdmin("admin"), Password=encryptAdmin(self._password)
        )
        token = result["token"]
        key = result["param0"]
        iv = result["param1"]

        encryptedToken = encryptToken(token, key, iv)
        self._token = encryptedToken
        # Save token to file
        self._saveToken()

        # Update headers with token
        self.session.headers["_TclRequestVerificationToken"] = self._token

    def _runCommand(self, command: str, **args):
        message = {"jsonrpc": "2.0", "method": command, "id": "12", "params": args}
        resp = self.session.post(self._url + "/jrd/webapi", json=message)
        result = resp.json()
        if "result" not in result:
            raise Exception(result["error"])

        return result["result"]

    def run(self, command: str, pretty: bool = False) -> str:
        # Login if needed
        if self._password is not None:
            if self._getLoginState() == False:
                self._login()

        result = self._runCommand(command)
        
        if pretty:
            result = json.dumps(result, indent=4, sort_keys=True)
            
        return result

    @staticmethod
    def printAvailableCommands():
        print("Commands that doesn't require login:")
        print("  GetCurrentLanguage")
        print("  GetSimStatus")
        print("  GetLoginState")
        print("  GetSystemStatus")
        print()
        print("Command that require login (add \"-p password\" to command line arguments)")
        print("  GetDeviceNewVersion")
        print("  GetNetworkInfo")
        print("  GetWanSettings")
        print("  GetWanIsConnInter")
        print("  GetSMSStorageState")
        print("  GetCallLogCountInfo")
        print("  GetActiveData")
        print("  GetConnectionSettings")
        print("  GetUsageSettings")
        print("  GetUsageRecord")
        print("  GetNetworkSettings")
        print("  GetNetworkRegisterState")
        print("  GetProfileList")
        print("  GetConnectionState")
        print("  GetLanSettings")
        print("  GetALGSettings")
        print("  getDMZInfo")
        print("  GetUpnpSettings")
        print("  getPortFwding")
        print("  getSmsInitState")
        print("  GetSMSListByContactNum")
        print("  GetSingleSMS")
        print("  GetSendSMSResult")
        print("  getSMSAutoRedirectSetting")
        print("  GetSMSSettings")
        print("  GetDdnsSettings")
        print("  GetDynamicRouting")
        print("  getIPFilterList")
        print("  GetMacFilterSettings")
        print("  GetParentalSettings")
        print("  GetConnectedDeviceList")
        print("  GetAutoValidatePinState")
        print("  GetStaticRouting")
        print("  getUrlFilterSettings")
        print("  GetVPNPassthrough")
        print("  getFirewallSwitch")
        print("  GetDLNASettings")
        print("  GetFtpSettings")
        print("  GetSambaSettings")
        print("  GetDeviceDefaultRight")
        print("  GetBlockDeviceList")
        print("  GetLanStatistics")
        print("  GetWlanSettings")
        print("  GetWlanStatistics")
        print("  getCurrentProfile")
        print("  GetLanPortInfo")
        print("  GetSystemInfo")
        print("  GetPasswordChangeFlag")
        print("  GetUSBLocalUpdateList")
        print("  GetSystemSettings")
        print("  GetDeviceUpgradeState")
        print("  GetCurrentTime")
        print("  GetClientConfiguration")
        print("  GetUSSDSendResult")
        print("  GetWanCurrentMacAddr")
        print("  GetCallLogList")
        print("  GetQosSettings")
        print("  GetVoicemail")