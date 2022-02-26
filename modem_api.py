import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode

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

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
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

    def _runCommand(self, command, **args):
        message = {"jsonrpc": "2.0", "method": command, "id": "12", "params": args}
        resp = self.session.post(self._url + "/jrd/webapi", json=message)
        result = resp.json()
        if "result" not in result:
            raise Exception(result["error"])

        return result["result"]

    def run(self, command: str):
        # Login if needed
        if self._password is not None:
            if self._getLoginState() == False:
                self._login()

        return self._runCommand(command)

