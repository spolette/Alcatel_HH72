
# Alcatel HH72 Link Hub LTE Routeur
## Purpose
This script allows getting informations from the modem through its webapi available at *http://modem_ip.com/jrd/webapi*

## Compatibility
This script has been tested with Alcatel HH72 (HUB72) LTE Modem, but it might also work with other Alcatel LTE modems.

## Install dependencies
```
pip install -r requirements.txt
```

## Usage
Syntax:
```
usage: main.py [-h] [-u URL] [-p PASSWORD] [-c CMD] [--pretty]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Modem URL
  -p PASSWORD, --password PASSWORD
                        Password to access restricted commands
  -c CMD, --cmd CMD     Command to be run
  --pretty              Pretty print JSON output
```
Example:
```
python main.py -c GetSystemStatus --pretty
```
Output example:
```json
{
    "ConnectionStatus": 2,
    "Conprofileerror": 0,
    "CurrentConnection": 1,
    "Domestic_Roaming": 1,
    "NetworkMode": 3,
    "NetworkName": "BYTEL",
    "NetworkType": 8,
    "Roaming": 1,
    "SignalStrength": 4,
    "SmsState": 2,
    "Ssid_2g": "alcatel",
    "Ssid_5g": "alcatel_5G",
    "Status": 0,
    "TotalConnNum": 1,
    "UsbName": "",
    "UsbStatus": 0,
    "VoLTE_Calling": 0,
    "WlanState": 1,
    "WlanState_2g": 1,
    "WlanState_5g": 1,
    "curr_num_2g": 0,
    "curr_num_5g": 0
}
```
If a command replies with the following error:
```
> python main.py -c GetLanSettings --pretty
```
```
The modem replied with an error message
  Error code: -32699
  Error message: Authentication Failure
```
It means that this command needs administrator priviledge. You need to pass the admin password in the command arguments:
```
> python main.py -c GetLanSettings -p TheAdminPassword --pretty
```
```json
{
    "DHCPLeaseTime": 12,
    "DHCPServerStatus": 1,
    "DNSAddress1": "",
    "DNSAddress2": "",
    "DNSMode": 0,
    "EndIPAddress": "192.168.1.200",
    "IPv4IPAddress": "192.168.1.1",
    "StartIPAddress": "192.168.1.100",
    "SubnetMask": "255.255.255.0"
}
```
## Available commands
### Commands that doesn't require login
```
GetCurrentLanguage
GetSimStatus
GetLoginState
GetSystemStatus
GetSystemInfo
```

### Command that require login (add "-p password" to command line arguments)
```
GetDeviceNewVersion
GetNetworkInfo
GetWanSettings
GetWanIsConnInter
GetSMSStorageState
GetCallLogCountInfo
GetActiveData
GetConnectionSettings
GetUsageSettings
GetUsageRecord
GetNetworkSettings
GetNetworkRegisterState
GetProfileList
GetConnectionState
GetLanSettings
GetALGSettings
getDMZInfo
GetUpnpSettings
getPortFwding
getSmsInitState
GetSMSListByContactNum
GetSingleSMS
GetSendSMSResult
getSMSAutoRedirectSetting
GetSMSSettings
GetDdnsSettings
GetDynamicRouting
getIPFilterList
GetMacFilterSettings
GetParentalSettings
GetConnectedDeviceList
GetAutoValidatePinState
GetStaticRouting
getUrlFilterSettings
GetVPNPassthrough
getFirewallSwitch
GetDLNASettings
GetFtpSettings
GetSambaSettings
GetDeviceDefaultRight
GetBlockDeviceList
GetLanStatistics
GetWlanSettings
GetWlanStatistics
getCurrentProfile
GetLanPortInfo
GetPasswordChangeFlag
GetUSBLocalUpdateList
GetSystemSettings
GetDeviceUpgradeState
GetCurrentTime
GetClientConfiguration
GetUSSDSendResult
GetWanCurrentMacAddr
GetCallLogList
GetQosSettings
GetVoicemail
```
