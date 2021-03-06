#!/usr/bin/env python3
import argparse
from modem_api import ModemAPI

def main():
    # Parse arguments
    argumentsParser = argparse.ArgumentParser()
    argumentsParser.add_argument("-u", "--url", help="Modem URL", default="http://192.168.1.1/", required=False)
    argumentsParser.add_argument("-p", "--password", help="Password to access restricted commands", required=False)
    argumentsParser.add_argument("-c", "--cmd", help="Command to be run", default="GetSystemStatus", required=False)
    argumentsParser.add_argument("--pretty", help="Pretty print JSON output", required=False, action='store_true')
    argumentsParser.add_argument("-l", "--list", help="Show available commands", action="store_true")
    params = argumentsParser.parse_args()

    if params.list:
        ModemAPI.printAvailableCommands()
        return

    api = ModemAPI(params.url)

    if params.password is not None:
        api.setPassword(params.password)

    try:
        result = api.run(params.cmd, params.pretty)
        print(result)

    except Exception as e:
        json = e.args[0]
        print("The modem replied with an error message")
        print(f'  Error code: {json["code"]}')
        print(f'  Error message: {json["message"]}')


if __name__ == "__main__":
    main()
