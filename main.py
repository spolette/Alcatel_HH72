#!/usr/bin/env python3
import argparse
from modem_api import ModemAPI

def main():
    # Parse arguments
    argumentsParser = argparse.ArgumentParser()
    argumentsParser.add_argument("-u", "--url", help="Modem URL", default="http://192.168.1.1/", required=False)
    argumentsParser.add_argument("-p", "--password", help="Password to access some restricted API", required=False)
    argumentsParser.add_argument("-c", "--cmd", help="Command to be sent", default="GetSystemStatus", required=False)
    
    params = argumentsParser.parse_args()

    api = ModemAPI(params.url)

    if params.password is not None:
        api.setPassword(params.password)

    result = api.run(params.cmd)

    print(result)

if __name__ == "__main__":
    main()