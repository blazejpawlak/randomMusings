#!/usr/bin/python
# -*- coding: utf-8 -*-

# Useful resources:
# - https://blog.hqcodeshop.fi/archives/259-Huawei-E5186-AJAX-API.html
# - http://www.bez-kabli.pl/viewtopic.php?t=43279
# - http://forum.jdtech.pl/Watek-hilink-api-dla-urzadzen-huawei?pid=29774#PIN
# - http://forum.jdtech.pl/Watek-hilink-api-dla-urzadzen-huawei?pid=29790#autopin
#
# Sample cron configuration
# * * * * * source ~/.profile; /usr/bin/python /storage/authLTE.py >> /storage/modem_auth.log
# * * * * * sleep 30; source ~/.profile; /usr/bin/python /storage/authLTE.py >> /storage/modem_auth.log
#

import sys
import requests
import re
import hashlib
import base64
import time
import ping
from bs4 import BeautifulSoup as Soup

# Statics
NOW = time.strftime("%Y/%m/%d %H:%M:%S")

# Configuration parameters
ROUTER_IP = '192.168.1.1'
BASE_URL = 'http://'+ROUTER_IP +'/'
PING_IP = '8.8.8.8'
USER_NAME = 'admin'
PASSWORD = 'admin'
SIM_PIN_CODE = 0000

# PIN status codes, from http://forum.jdtech.pl/Watek-hilink-api-dla-urzadzen-huawei?pid=29774#PIN
PIN_STATUS_CODES = { 255 : "No SIM card present",
                     256 : "CPIN error",
                     257 : "SIM ready",
                     258 : "PIN disabled",
                     259 : "PIN being checked",
                     260 : "PIN entry required",
                     261 : "PUK entry required"
}

# List of return codes from https://github.com/HSPDev/Huawei-E5180-API
RETURN_CODES = {    -1 : "ERROR_DEFAULT",
                    -2 : "ERROR_NO_DEVICE",
                    1 : "ERROR_FIRST_SEND",
                    100001 : "ERROR_UNKNOWN",
                    100002 : "ERROR_NOT_SUPPORT",
                    100003 : "ERROR_NO_RIGHT",
                    100005 : "ERROR_FORMAT_ERROR",
                    100006 : "ERROR_PARAMETER_ERROR",
                    100007 : "ERROR_SAVE_CONFIG_FILE_ERROR",
                    100008 : "ERROR_GET_CONFIG_FILE_ERROR",
                    101001 : "ERROR_NO_SIM_CARD_OR_INVALID_SIM_CARD",
                    101002 : "ERROR_CHECK_SIM_CARD_PIN_LOCK",
                    101003 : "ERROR_CHECK_SIM_CARD_PUN_LOCK",
                    101004 : "ERROR_CHECK_SIM_CARD_CAN_UNUSEABLE",
                    101005 : "ERROR_ENABLE_PIN_FAILED",
                    101006 : "ERROR_DISABLE_PIN_FAILED",
                    101007 : "ERROR_UNLOCK_PIN_FAILED",
                    101008 : "ERROR_DISABLE_AUTO_PIN_FAILED",
                    101009 : "ERROR_ENABLE_AUTO_PIN_FAILED",
                    102001 : "ERROR_GET_NET_TYPE_FAILED",
                    102002 : "ERROR_GET_SERVICE_STATUS_FAILED",
                    102003 : "ERROR_GET_ROAM_STATUS_FAILED",
                    102004 : "ERROR_GET_CONNECT_STATUS_FAILED",
                    103001 : "ERROR_DEVICE_AT_EXECUTE_FAILED",
                    103002 : "ERROR_DEVICE_PIN_VALIDATE_FAILED",
                    103003 : "ERROR_DEVICE_PIN_MODIFFY_FAILED",
                    103004 : "ERROR_DEVICE_PUK_MODIFFY_FAILED",
                    103005 : "ERROR_DEVICE_GET_AUTORUN_VERSION_FAILED",
                    103006 : "ERROR_DEVICE_GET_API_VERSION_FAILED",
                    103007 : "ERROR_DEVICE_GET_PRODUCT_INFORMATON_FAILED",
                    103008 : "ERROR_DEVICE_SIM_CARD_BUSY",
                    103009 : "ERROR_DEVICE_SIM_LOCK_INPUT_ERROR",
                    103010 : "ERROR_DEVICE_NOT_SUPPORT_REMOTE_OPERATE",
                    103011 : "ERROR_DEVICE_PUK_DEAD_LOCK",
                    103012 : "ERROR_DEVICE_GET_PC_AISSST_INFORMATION_FAILED",
                    103013 : "ERROR_DEVICE_SET_LOG_INFORMATON_LEVEL_FAILED",
                    103014 : "ERROR_DEVICE_GET_LOG_INFORMATON_LEVEL_FAILED",
                    103015 : "ERROR_DEVICE_COMPRESS_LOG_FILE_FAILED",
                    103016 : "ERROR_DEVICE_RESTORE_FILE_DECRYPT_FAILED",
                    103017 : "ERROR_DEVICE_RESTORE_FILE_VERSION_MATCH_FAILED",
                    103018 : "ERROR_DEVICE_RESTORE_FILE_FAILED",
                    103101 : "ERROR_DEVICE_SET_TIME_FAILED",
                    103102 : "ERROR_COMPRESS_LOG_FILE_FAILED",
                    104001 : "ERROR_DHCP_ERROR",
                    106001 : "ERROR_SAFE_ERROR",
                    107720 : "ERROR_DIALUP_GET_CONNECT_FILE_ERROR",
                    107721 : "ERROR_DIALUP_SET_CONNECT_FILE_ERROR",
                    107722 : "ERROR_DIALUP_DIALUP_MANAGMENT_PARSE_ERROR",
                    107724 : "ERROR_DIALUP_ADD_PRORILE_ERROR",
                    107725 : "ERROR_DIALUP_MODIFY_PRORILE_ERROR",
                    107726 : "ERROR_DIALUP_SET_DEFAULT_PRORILE_ERROR",
                    107727 : "ERROR_DIALUP_GET_PRORILE_LIST_ERROR",
                    107728 : "ERROR_DIALUP_GET_AUTO_APN_MATCH_ERROR",
                    107729 : "ERROR_DIALUP_SET_AUTO_APN_MATCH_ERROR",
                    108001 : "ERROR_LOGIN_NO_EXIST_USER",
                    108002 : "ERROR_LOGIN_PASSWORD_ERROR",
                    108003 : "ERROR_LOGIN_ALREADY_LOGINED",
                    108004 : "ERROR_LOGIN_MODIFY_PASSWORD_FAILED",
                    108005 : "ERROR_LOGIN_TOO_MANY_USERS_LOGINED",
                    108006 : "ERROR_LOGIN_USERNAME_OR_PASSWORD_ERROR",
                    108007 : "ERROR_LOGIN_TOO_MANY_TIMES",
                    109001 : "ERROR_LANGUAGE_GET_FAILED",
                    109002 : "ERROR_LANGUAGE_SET_FAILED",
                    110001 : "ERROR_ONLINE_UPDATE_SERVER_NOT_ACCESSED",
                    110002 : "ERROR_ONLINE_UPDATE_ALREADY_BOOTED",
                    110003 : "ERROR_ONLINE_UPDATE_GET_DEVICE_INFORMATION_FAILED",
                    110004 : "ERROR_ONLINE_UPDATE_GET_LOCAL_GROUP_COMMPONENT_INFORMATION_FAILED",
                    110005 : "ERROR_ONLINE_UPDATE_NOT_FIND_FILE_ON_SERVER",
                    110006 : "ERROR_ONLINE_UPDATE_NEED_RECONNECT_SERVER",
                    110007 : "ERROR_ONLINE_UPDATE_CANCEL_DOWNLODING",
                    110008 : "ERROR_ONLINE_UPDATE_SAME_FILE_LIST",
                    110009 : "ERROR_ONLINE_UPDATE_CONNECT_ERROR",
                    110021 : "ERROR_ONLINE_UPDATE_INVALID_URL_LIST",
                    110022 : "ERROR_ONLINE_UPDATE_NOT_SUPPORT_URL_LIST",
                    110023 : "ERROR_ONLINE_UPDATE_NOT_BOOT",
                    110024 : "ERROR_ONLINE_UPDATE_LOW_BATTERY",
                    11019 : "ERROR_USSD_NET_NO_RETURN",
                    111001 : "ERROR_USSD_ERROR",
                    111012 : "ERROR_USSD_FUCNTION_RETURN_ERROR",
                    111013 : "ERROR_USSD_IN_USSD_SESSION",
                    111014 : "ERROR_USSD_TOO_LONG_CONTENT",
                    111016 : "ERROR_USSD_EMPTY_COMMAND",
                    111017 : "ERROR_USSD_CODING_ERROR",
                    111018 : "ERROR_USSD_AT_SEND_FAILED",
                    111020 : "ERROR_USSD_NET_OVERTIME",
                    111021 : "ERROR_USSD_XML_SPECIAL_CHARACTER_TRANSFER_FAILED",
                    111022 : "ERROR_USSD_NET_NOT_SUPPORT_USSD",
                    112001 : "ERROR_SET_NET_MODE_AND_BAND_WHEN_DAILUP_FAILED",
                    112002 : "ERROR_SET_NET_SEARCH_MODE_WHEN_DAILUP_FAILED",
                    112003 : "ERROR_SET_NET_MODE_AND_BAND_FAILED",
                    112004 : "ERROR_SET_NET_SEARCH_MODE_FAILED",
                    112005 : "ERROR_NET_REGISTER_NET_FAILED",
                    112006 : "ERROR_NET_NET_CONNECTED_ORDER_NOT_MATCH",
                    112007 : "ERROR_NET_CURRENT_NET_MODE_NOT_SUPPORT",
                    112008 : "ERROR_NET_SIM_CARD_NOT_READY_STATUS",
                    112009 : "ERROR_NET_MEMORY_ALLOC_FAILED",
                    113017 : "ERROR_SMS_NULL_ARGUMENT_OR_ILLEGAL_ARGUMENT",
                    113018 : "ERROR_SMS_OVERTIME",
                    113020 : "ERROR_SMS_QUERY_SMS_INDEX_LIST_ERROR",
                    113031 : "ERROR_SMS_SET_SMS_CENTER_NUMBER_FAILED",
                    113036 : "ERROR_SMS_DELETE_SMS_FAILED",
                    113047 : "ERROR_SMS_SAVE_CONFIG_FILE_FAILED",
                    113053 : "ERROR_SMS_LOCAL_SPACE_NOT_ENOUGH",
                    113054 : "ERROR_SMS_TELEPHONE_NUMBER_TOO_LONG",
                    114001 : "ERROR_SD_FILE_EXIST",
                    114002 : "ERROR_SD_DIRECTORY_EXIST",
                    114004 : "ERROR_SD_FILE_OR_DIRECTORY_NOT_EXIST",
                    114004 : "ERROR_SD_IS_OPERTED_BY_OTHER_USER",
                    114005 : "ERROR_SD_FILE_NAME_TOO_LONG",
                    114006 : "ERROR_SD_NO_RIGHT",
                    114007 : "ERROR_SD_FILE_IS_UPLOADING",
                    115001 : "ERROR_PB_NULL_ARGUMENT_OR_ILLEGAL_ARGUMENT",
                    115002 : "ERROR_PB_OVERTIME",
                    115003 : "ERROR_PB_CALL_SYSTEM_FUCNTION_ERROR",
                    115004 : "ERROR_PB_WRITE_FILE_ERROR",
                    115005 : "ERROR_PB_READ_FILE_ERROR",
                    115199 : "ERROR_PB_LOCAL_TELEPHONE_FULL_ERROR",
                    116001 : "ERROR_STK_NULL_ARGUMENT_OR_ILLEGAL_ARGUMENT",
                    116002 : "ERROR_STK_OVERTIME",
                    116003 : "ERROR_STK_CALL_SYSTEM_FUCNTION_ERROR",
                    116004 : "ERROR_STK_WRITE_FILE_ERROR",
                    116005 : "ERROR_STK_READ_FILE_ERROR",
                    117001 : "ERROR_WIFI_STATION_CONNECT_AP_PASSWORD_ERROR",
                    117002 : "ERROR_WIFI_WEB_PASSWORD_OR_DHCP_OVERTIME_ERROR",
                    117003 : "ERROR_WIFI_PBC_CONNECT_FAILED",
                    117004 : "ERROR_WIFI_STATION_CONNECT_AP_WISPR_PASSWORD_ERROR",
                    118001 : "ERROR_CRADLE_GET_CRURRENT_CONNECTED_USER_IP_FAILED",
                    118002 : "ERROR_CRADLE_GET_CRURRENT_CONNECTED_USER_MAC_FAILED",
                    118003 : "ERROR_CRADLE_SET_MAC_FAILED",
                    118004 : "ERROR_CRADLE_GET_WAN_INFORMATION_FAILED",
                    118005 : "ERROR_CRADLE_CODING_FAILED",
                    118006 : "ERROR_CRADLE_UPDATE_PROFILE_FAILED",
                    125001 : "ERROR_WRONG_TOKEN",
                    125002 : "ERROR_WRONG_SESSION",
                    125003 : "ERROR_WRONG_SESSION_TOKEN",
                    100004 : "ERROR_BUSY"
                }

_session = None
_csrf_tokens = None

def _grep_csrf(html):
    pat = re.compile(r".*meta name=\"csrf_token\" content=\"(.*)\"", re.I)
    matches = (pat.match(line) for line in html.splitlines())

    return [m.group(1) for m in matches if m]

def _login_data(username, password, csrf_token):
    def encrypt(text):
        m = hashlib.sha256()
        m.update(text)
        return base64.b64encode(m.hexdigest())

    password_hash = encrypt(username + encrypt(password) + csrf_token)

    # XMLify the request
    xml = """<?xml version="1.0" encoding="UTF-8"?><request><Username>%s</Username><Password>%s</Password><password_type>4</password_type></request>""" % (username, password_hash)

    return xml

def _getSession():
    global _session
    global _csrf_tokens

    if _session == None:
        _session = requests.Session()
        request = _session.get(BASE_URL + 'html/index.html')
        _csrf_tokens = _grep_csrf(request.text)

        _session.headers.update({
            '__RequestVerificationToken': _csrf_tokens[0]
        })

    return _session

def reboot():
    if isLoggedIn() == False:
        login()

    session = _getSession()
    xml = """<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>"""
    request = session.post(BASE_URL + "api/device/control", data=xml)

    session.headers.update({
        '__RequestVerificationToken': request.headers["__RequestVerificationToken"]
    })

    # Check the response
    soup = Soup(request.text, 'html.parser')

    if soup.find('error') != None:
        raise Exception('Reboot failed with error code: ' + soup.find('error').code.text +
                        '. Code explanation: ' + RETURN_CODES[int(soup.find('error').code.text)] +
                        '. Message: ' + soup.find('error').message.text)

    if soup.response != None and soup.response.text != "OK":
        raise Exception('Reboot failed with: ' + soup.text)

def reachabilityTest( pAddress ):
    # NOTE: Requires root access
    if ping.do_one(pAddress, 5, 1) == None:
        return False
    else:
        return True

def isLoggedIn():
    session = _getSession()
    request = session.get(BASE_URL + 'api/user/state-login')

    # Parse the response
    soup = Soup(request.text, 'html.parser')

    if soup.find('error') != None:
        raise Exception('Logon check failed with error code: ' + soup.find('error').code.text +
                        '. Code explanation: ' + RETURN_CODES[int(soup.find('error').code.text)] +
                        '. Message: ' + soup.find('error').message.text)

    if soup.find('response') != None:
        if int(soup.find('response').state.text) == -1:
            return False
        else:
            return True

    return False

def login():
    session = _getSession()
    csrf_tokens = _csrf_tokens

    data = _login_data(USER_NAME, PASSWORD, csrf_tokens[0])
    request = session.post(BASE_URL + 'api/user/login', data=data)

    # Check the response
    soup = Soup(request.text, 'html.parser')

    if soup.find('error') != None:
        raise Exception('Logon failed with error code: ' + soup.find('error').code.text +
                        '. Code explanation: ' + RETURN_CODES[int(soup.find('error').code.text)] +
                        '. Message: ' + soup.find('error').message.text)

    if soup.response != None and soup.response.text != "OK":
        raise Exception('Logon failed with: ' + soup.text)

    session.headers.update({
        '__RequestVerificationToken': request.headers["__RequestVerificationTokenone"]
    })

    return session

def logout():
    session = _getSession()

    xml = """<?xml version:"1.0" encoding="UTF-8"?><request><Logout>1</Logout></request>"""
    request = session.post(BASE_URL + 'api/user/logout', data=xml)

    session.headers.update({
        '__RequestVerificationToken': request.headers["__RequestVerificationToken"]
    })

    # Check the response
    soup = Soup(request.text, 'html.parser')

    if soup.find('error') != None:
        raise Exception('Logout failed with error code: ' + soup.find('error').code.text +
                        '. Code explanation: ' + RETURN_CODES[int(soup.find('error').code.text)] +
                        '. Message: ' + soup.find('error').message.text)

    if soup.response != None and soup.response.text != "OK":
        raise Exception('Logout failed with: ' + soup.text)


def isSimUnlocked():
    session = _getSession()
    request = session.get(BASE_URL + 'api/pin/status')

    soup = Soup(request.text, 'html.parser')
    simState = int(soup.response.simstate.text)

    # Check whether we need to authenticate with SIM PIN code
    if simState == 260:
        return False
    elif simState == 257:
        return True
    else:
        raise Exception('Unknown SIM status: ' + str(simState) + " - " + PIN_STATUS_CODES[simState])

def unlockSimCard():
    session = _getSession()

    xml = """<request><OperateType>0</OperateType><CurrentPin>%s</CurrentPin><NewPin></NewPin><PukCode></PukCode></request>""" % (SIM_PIN_CODE)
    request = session.post(BASE_URL + "api/pin/operate", data=xml)

    session.headers.update({
        '__RequestVerificationToken': request.headers["__RequestVerificationToken"]
    })

    soup = Soup(request.text, 'html.parser')

    if soup.find('error') != None:
        raise Exception('SIM authentication failed with error code: ' + soup.find('error').code.text +
                        '. Code explanation: ' + RETURN_CODES[int(soup.find('error').code.text)] +
                        '. Message: ' + soup.find('error').message.text)

    if soup.response != None and soup.response.text != "OK":
        raise Exception('Logon failed with: ' + soup.text)

def main():
    # Check whether we can reach the Internet, if so, do nothing
    if reachabilityTest(PING_IP) != True:
        sys.exit(0)
    else:
        print NOW + ' [info] No Internet connection. Attempting reconnection...'

        try:
            # The Internet is not reachable, check whether the modem is reachable
            if reachabilityTest(ROUTER_IP) == False:
                print NOW + ' [error] Cannot reach the modem IP address.'
                exit(100)
            else:
                # Check whether we're logged in
                if isLoggedIn() == False:
                    print NOW + ' [info] Logging on...'
                    login()
                    print NOW + ' [info] Logged on!'

                # Check again, to be sure whether we're logged on and the session is established
                if isLoggedIn() == False:
                    print NOW + ' [error] Logon failed even though we tried.'

                # Check whether the SIM card is unlocked; unlock if locked
                if isSimUnlocked() == False:
                    print NOW + ' [info] SIM Card locked, unlocking...'
                    unlockSimCard()
                    logout()
                    print NOW + ' [info] SIM Card successfully unlocked.'

                    # Wait a few seconds and try to connect the Google's DNS service
                    time.sleep(15)
                if reachabilityTest(PING_IP) == False:
                    print NOW + '[INFO] Still no internet connection. Rebooting'
                    reboot()
                    # it takes about 45 secs to reboot, but will give some extra time
                    time.sleep(60)

                if reachabilityTest(PING_IP) == False:
                    print NOW + ' [error] Still no Internet connection. Aborting.'
                    exit(101)
                else:
                    print NOW + ' [info] Modem is connected to the Internet!'
        except Exception as e:
            print NOW + ' [error] Failed with exception: ' + str(e[0])

if __name__ == "__main__":
    main()
    # reboot()
