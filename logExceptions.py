# ~TestCaseName: logExceptions
# ~TestCaseSummary: This is a library module for storing a master list of logfile exceptions

__author__ = 'Chris Maurer (chris.maurer@tradingtechnologies.com)'
__version__ = '2.0'

import re


def logexceptions(gw_flavour):
    """Return a list of compiled real expressions for general log exceptions and GW specific ones

    These will be ignored by AnaLog when generating logfile analysis reports."""
    _logexceptions = [
        # Ignore messages from Guardian and Guardserver.
        re.compile(r'.*\| guardserv.exe/(SIM|PROD) \|.*', re.I),
        re.compile(r'.*\| guardian.exe/(SIM|PROD) \|.*', re.I),
        re.compile(r'.*Sending status due to Guardian.*', re.I),
        re.compile(r'.*License not received, trying again.*', re.I),
        re.compile(r'.*Limit request failed.*', re.I),
        re.compile(r'.*product table.*', re.I),
        re.compile(r'.*currency table.*', re.I),
        re.compile(r'.*DH (params|Parameters).*', re.I),
        re.compile(r'.*(DHInit|DHDecrypt) failed.*', re.I),
        re.compile(r'.*Order key file not found.*', re.I),
        re.compile(r'.*accepted my login.*', re.I),
        re.compile(r'.*Guard.*00000000.*', re.I),
        # Ignore server and client status messages.
        re.compile(r'.*SERVER is.*', re.I),
        re.compile(r'.*Risk server ip.*', re.I),
        re.compile(r'.*XAdmin.*', re.I),
        re.compile(r'.*TT_CLIENT_.*', re.I),
        re.compile(r'.*TT_NO_CLIENT.*', re.I),
        re.compile(r'.*CheckConnection: Connection to client.*', re.I),
        # Ignore all messages related to Login / Auto-Login.
        re.compile(r'.*10001478.*', re.I),
        re.compile(r'.*10002449.*', re.I),
        re.compile(r'.*1000461(4|5).*', re.I),
        re.compile(r'.*1010105(1|2).*', re.I),
        re.compile(r'.*10001185.*', re.I),
        # Ignore all 'snmp' messages.
        re.compile(r'.*snmp.exe.*', re.I),
        # Ignore all TTM Advisory messages.
        re.compile(r'.*TTM Advisory.*', re.I),
        # This message is caused by a known defect; and should be removed once PCR 97315 is fixed.
        re.compile(r'.*In VIAMessaging ConsumerThread.*Cannot send message.*Session is not active.*', re.I),
        # Ignore client connection messages.
        re.compile(r'.*closed connection.*', re.I),
        # Ignore going online messages.
        re.compile(r'.*Going online.*', re.I),
        # Ignore OpenExchangePrices messages.
        re.compile(r'.*OpenExchangePrices.*', re.I),
        # ignore RequestTimeoutTCB messages
        re.compile(r'.*RequestTimeoutTCB.*', re.I),
        # Ignore manual server shutdown messages.
        re.compile(r'.*normal termination.*', re.I),
        # Ignore Client App Connection ID mismatch messages.
        re.compile(r'.*Connection ID mismatch.*', re.I),
        # Ignore client status messages.
        re.compile(r'.*consecutive client status messages.*', re.I),
        # Ignore Bad status REJECT messages.
        re.compile(r'.*Bad status REJECT.*', re.I),
        re.compile(r'.*processDeleteOrder: bad status.*', re.I),
        re.compile(r'.*exchange_order_id.*', re.I),
        re.compile(r'.*Normal OS.*', re.I),
        # Ignore BOF File handling messages.
        re.compile(r'.*no fills are read from the file.*', re.I),
        re.compile(r'.*_bof.tbl doesn\'t exist. New file will be created.*', re.I),
        re.compile(r'.*_bof.tbl is empty. Nothing could be trimmed.*', re.I),
        re.compile(r'.*_bof.bak: The system cannot find the file specified.*', re.I),
        re.compile(r'.*Delete your fills.tbl file.*', re.I),
        # Ignore Exchange-side disconnects
        re.compile(r'.*logout message received from host.*', re.I),
        # Ignore "Could not connect" messages.
        re.compile(r'.*Could not connect.*', re.I),
        # Ignore "system error occurred on 'connect'" messages.
        re.compile(r'.*system error occured on \'connect\'.*', re.I),
        # Ignore "Error logging in to exchange" messages.
        re.compile(r'.*Error logging in to exchange.*', re.I),
        # Ignore "Login is disabled" messages.
        re.compile(r'.*Login is disabled.*', re.I),
        # Ignore "invalid login attempt" messages.
        re.compile(r'.*EX: invalid login attempt.*', re.I),
        # Ignore "User is suspended" messages.
        re.compile(r'.*EX: Login denied. User is suspended.*', re.I),
        # Ignore "Could not init exchange API" messages.
        re.compile(r'.*Could not init exchange.*', re.I),
        # Ignore "Could not init TTAPI" messages.
        re.compile(r'.*Could not init TTAPI.*', re.I),
        # Ignore "Could not initialize server" messages.
        re.compile(r'.*Could not initialize (price|order) server*', re.I),
        # Ignore "Could not initialize session" messages.
        re.compile(r'.*Could not initialize (price|order) session*', re.I),
        # Ignore "initialization timed out" messages.
        re.compile(r'.*server initialization timed out after 30 sec*', re.I),
        # Ignore "Fill session not running" messages.
        re.compile(r'.*Fill session not running.*', re.I),
        # Ignore "Product "" is empty" messages.
        re.compile(r'.*Product \"\" is empty.*', re.I),
        # Ignore "so cannot send quote reject" messages.
        re.compile(r'.*so cannot send quote reject.*', re.I),
        # Ignore "fills.bak: The system cannot find the file specified" messages.
        re.compile(r'.*fills.bak: The system cannot find the file specified.*', re.I),
        # Ignore "LoginClient failed" messages.
        re.compile(r'.*LoginClient failed.*', re.I),
        # Ignore "Couldn't find exchange trader mapping: TTADM" messages.
        re.compile(r'.*Couldn\'t find exchange trader mapping: TTADM.*', re.I),
        # Ignore "The connection to the server was broken" messages.
        re.compile(r'.*The connection to the server was broken.*', re.I),
        # Ignore "Warnings about TTADM attempting to trade" messages.
        re.compile(r'.*Login access level does not permit order add.*', re.I),
        # Ignore mis-matched token messages.
        re.compile(r'.*Calced and rcvd tokens don\'t match.*', re.I),
        # Ignore deprecated messages from SuperGuardian
        re.compile(r'.*TT_PROC_NAME_REQUEST.*', re.I),
        # PRICE PROXY
        # As per Core Team, Ignore "No encryption" messages when they're from Proxy
        re.compile(r'.*priceproxy.exe/PROD | .... | WARNING | 10004009 | DHEncryptParam: No encryption performed.*',
                   re.I),
        # INFO Messages to ignore #####
        # Server Capability Flag
        re.compile(r'.*10101039.*', re.I),
        # Circuit Breaker
        re.compile(r'.*10011229.*', re.I),
        # Orders and RFQs
        re.compile(r'.*10069464 | OnTradeRFQ AMR.*', re.I),
        re.compile(r'.*10012002.*', re.I),
        re.compile(r'.*10012036.*', re.I),
        re.compile(r'.*10098022.*', re.I),
        re.compile(r'.*10012037.*', re.I),
        re.compile(r'.*10012038.*', re.I),
        re.compile(r'.*10098012.*', re.I),
        # Product Download and onControlMode
        re.compile(r'.*10011233.*', re.I),
        re.compile(r'.*10013155.*', re.I),
        re.compile(r'.*10116044.*', re.I),
        # Subscribe/Request Prices / Create Strategy
        re.compile(r'.*10002375.*', re.I),
        re.compile(r'.*10002383.*', re.I),
        re.compile(r'.*10002384.*', re.I),
        re.compile(r'.*10002407.*', re.I),
        re.compile(r'.*10002405.*', re.I),
        re.compile(r'.*10013158.*', re.I),
        re.compile(r'.*10011244.*', re.I),
        re.compile(r'.*10001586.*', re.I),
        # Trading State Changes
        re.compile(r'.*10069465.*', re.I),
        # Loading Aconfig Settings
        re.compile(r'.*10000032.*', re.I),
        # Create Buffer
        re.compile(r'.*10011007.*', re.I),
        # Mutex lock failed: Cannot create a file when that file already exists.
        re.compile(r'.*10136314.*', re.I),
        # Ignore INFO 10012213 "change clearing date"
        re.compile(r'.*10012213.*', re.I),
        # Ignore WARNING 10098037 "Price API: Unhandled TT CODE TT_PRODTBL_UPDATED"
        re.compile(r'.*Price API: Unhandled TT CODE TT_PRODTBL_UPDATED.*', re.I),
        # Ignore "Data lost on PGM stream"
        re.compile(r'.*10118042 | Data lost on PGM stream.*', re.I),
        # Ignore "Local Publisher::ResolveSubscribers push failed. Dropping data!"
        re.compile(r'.*Local Publisher::ResolveSubscribers push failed. Dropping data!.*', re.I),
        # Ignore "10118737 | PGM receive socket <ip_addr>: max pending bytes in last minute: n"
        re.compile(r'.*max pending bytes in last minute.*', re.I)
    ]
    if any(gwFlavourName in gw_flavour for gwFlavourName in ['SGX', 'TOCOM', 'OSE', 'HKEx']):
        _logexceptions.extend(om_exceptions())
    elif 'BTEC' in gw_flavour:
        _logexceptions.extend(btec_exceptions())
    elif 'ICE' in gw_flavour:
        _logexceptions.extend(ice_exceptions())
    elif 'CME' in gw_flavour or 'CBOT' in gw_flavour:
        _logexceptions.extend(fix_exceptions())
    elif 'LME' in gw_flavour:
        _logexceptions.extend(lme_exceptions())
    elif 'MEFF' in gw_flavour:
        _logexceptions.extend(meff_exceptions())
    elif 'NYSE_Liffe' in gw_flavour:
        _logexceptions.extend(nyse_liffe_exceptions())
    _logexceptions.extend(fillserver_exceptions())
    _logexceptions.extend(ttm_exceptions())
    return _logexceptions


def fillserver_exceptions():
    _fillserver_exceptions = [
        re.compile(r'.*Client download has been inactive for longer than 90 seconds.*', re.I),
        # Ignore "Failed to find sequence in either cache or files. Downloading all fills" messages
        re.compile(r'.*10071248.*', re.I),
        # FillSinkHandler source sequence adjustments
        re.compile(r'.*10101103.*', re.I),
        # Server / Connected client license list has not been received yet
        re.compile(r'.*10101007.*', re.I),
        re.compile(r'.*10101067.*', re.I)
    ]
    return _fillserver_exceptions


def ttm_exceptions():
    _ttm_exceptions = [
        re.compile(r'.*Old data received.*', re.I),
        # FillSinkHandler source sequence adjustments
        re.compile(r'.*10101103.*', re.I),
        # Too much data has been lost
        re.compile(r'.*10118074.*', re.I),
        # Cleaned up empty queues for process
        re.compile(r'.*10119386.*', re.I)
    ]
    return _ttm_exceptions


def om_exceptions():
    _om_exceptions = [
        # Ignore "[DA122] missing classBasic" messages.
        re.compile(r'.*missing classBasic.*', re.I),
        # Ignore "[DA120] missing underlyingBasic" messages.
        re.compile(r'.*missing underlyingBasic.*', re.I),
        # Ignore bad Cabinet Price Data messages
        re.compile(r'.*but not equal its cabinet price.*', re.I),
        # Ignore "cannot find order" messages
        re.compile(r'.*ConstructTTOrder cannot find order.*', re.I),
        # Ignore "RQ36: invalid transaction type" messages
        re.compile(r'.*RQ36: invalid transaction type.*', re.I),
        # Ignore "greeks" messages
        re.compile(r'.*greeks.*', re.I),
        # Ignore "Login is disabled" messages.
        re.compile(r'.*Login is disabled.*', re.I),
        # Ignore all "password change" related messages.
        re.compile(r'.*10011012.*', re.I),
        # Ignore "MakeTTFillFromOrderAndOMFill" messages.
        re.compile(r'.*MakeTTFillFromOrderAndOMFill passthrough_s.*', re.I),
        # Ignore "failure completion" messages
        re.compile(r'.*failure completion.*', re.I),
        # Ignore "IsDetailDepthValid" messages
        re.compile(r'.*invalid data: prevPrice =.*', re.I),
        # Ignore "cannot find instrument series" messages
        re.compile(r'.*cannot find instrument series.*', re.I),
        # Ignore "missing market_info_series" messages
        re.compile(r'.*missing market_info_series.*', re.I),
        # Ignore "cannot find comb code for series"
        re.compile(r'.*10011043.*', re.I),
        # Ignore "10013044 | Could not find any products matching "NK225""
        re.compile(r'.*Could not find any products matching \"NK225\".*', re.I),
        # Ignore "[BI7] Error in IQ42 query" messages
        re.compile(r'.*10013088.*', re.I),
        # Ignore "Failed to handle login request due to it being an invalid connection" messages
        re.compile(r'.*Failed to handle login request due to it being an invalid connection.*', re.I),
        # Ignore "Could not download one-sided orders" messages
        re.compile(r'.*Could not download one-sided orders.*', re.I)
    ]
    return _om_exceptions


def ice_exceptions():
    _ice_exceptions = [
        # Ignore "Cannot send message" messages.
        re.compile(r'.*(Cannot|Can not) send message.*', re.I),
        # Ignore "exceeds the highest sequence number" messages.
        re.compile(r'.*exceeds the highest sequence number.*', re.I),
        # Ignore "Record w/ seqNo" messages.
        re.compile(r'.*Record w/ seqNo.*', re.I),
        # Ignore "Market type not supported" messages.
        re.compile(r'.*Market type not supported.*', re.I),
        # Ignore "does not support quoting" messages.
        re.compile(r'.*ICE does not support quoting.*', re.I),
        # Ignore "Proxy/Adminstrative traders will not be logged in" messages
        re.compile(r'.*(Proxy|Adminstrative) traders will not be logged into the exchange.*', re.I),
        # Ignore "Product name is too large for the price subject" [PCR 132845] messages
        re.compile(r'.*Product name is too large for the price subject.*', re.I),
        # Ignore "Received unknown message type: M" [PCR 132845] messages
        re.compile(r'.*Received unknown message type: M.*', re.I),
        # Ignore "Unable to find price table entry for market id" messages.
        re.compile(r'.*Unable to find price table entry for market id.*', re.I)
    ]
    return _ice_exceptions


def btec_exceptions():
    _btec_exceptions = [
        # Ignore "PriceEvent::HandleDepth" messages.
        re.compile(r'.*10013093.*', re.I),
        # Ignore "Login request has been rejected" messages.
        re.compile(r'.*10004617.*', re.I),
        # Ignore "is longer than 19 characters" messages
        re.compile(r'.*is longer than 19 characters.*', re.I),
        # Ignore "Product name is too large for the price subject" messages
        re.compile(r'.*10001643.*', re.I),
        # Ignore Unsupported trading state messages
        re.compile(r'.*10011048.*', re.I),
        # Ignore "session not connected" messages
        re.compile(r'.*10011012.*', re.I),
        # Ignore "session not running" messages
        re.compile(r'.*session not running.*', re.I),
    ]
    return _btec_exceptions


def fix_exceptions():
    _fix_exceptions = [
        # Ignore "Can not send message" messages
        re.compile(r'.*Can not send message to daemon.*', re.I),
        # Ignore "Connection rejected" messages
        re.compile(r'.*Connection rejected, status not active.*', re.I),
        # Ignore "tokens don't match" messages
        re.compile(r'.*Calced and rcvd tokens don\'t match.*', re.I),
        # Ignore "TT_PROC_NAME_REQUEST" messages
        re.compile(r'.*TT_PROC_NAME_REQUEST.*', re.I),
        # Ignore "Socket connect failed" messages
        re.compile(r'.*Socket connect failed.*', re.I),
        # Ignore "Failed to get connection information" messages
        re.compile(r'.*Failed to get connection information for handling order.*', re.I),
        # Message Gap Detected / Timeout messages
        re.compile(r'.*Message Gap (Detected|Timeout).*', re.I),
        # Retransmission Complete
        re.compile(r'.*10088044.*', re.I)
    ]
    return _fix_exceptions


def lme_exceptions():
    _lme_exceptions = [
        # Ignore "Failed to find optional tag 41" messages
        re.compile(r'.*Failed to find optional tag 41.*', re.I)
    ]
    return _lme_exceptions


def meff_exceptions():
    _meff_exceptions = [
        # Ignore "Connection rejected, status not active" messages
        re.compile(r'.*Connection rejected, status not active.*', re.I),
        # Ignore "No message cache file specified in configuration file" messages
        re.compile(r'.*No message cache file specified in configuration file.*', re.I),
        # Ignore "No message cache file specified in configuration file" messages
        re.compile(r'.*No message cache file specified in configuration file.*', re.I),
        # Ignore "A socket error was encountered" messages
        re.compile(r'.*A socket error was encountered.*', re.I),
        # Ignore "Failed to initialize Data Stream Manager" messages
        re.compile(r'.*Failed to initialize Data Stream Manager.*', re.I),
        # Ignore "Overall state of component is not acceptable" messages
        re.compile(r'.*Overall state of component is not acceptable.*', re.I)
    ]
    return _meff_exceptions


def nyse_liffe_exceptions():
    _nyse_liffe_exceptions = [
        # Ignore "Price Update Received for Unknown Instrument" messages
        re.compile(r'.*Price Update Received for Unknown Instrument.*', re.I)
    ]
    return _nyse_liffe_exceptions
