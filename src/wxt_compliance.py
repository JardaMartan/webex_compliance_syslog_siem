#!/bin/#!/usr/bin/env python3

import os
import sys
import uuid
import logging
import coloredlogs
import inspect
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from urllib.parse import urlparse, quote

from webexteamssdk import WebexTeamsAPI, ApiError, AccessToken
webex_api = WebexTeamsAPI(access_token="12345")

import json, requests
from datetime import datetime, timedelta, timezone
import time
from flask import Flask, request, redirect, url_for, make_response

import re
import pysyslogclient
import base64

import concurrent.futures
import signal

flask_app = Flask(__name__)
flask_app.config["DEBUG"] = True
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)7s]  [%(module)s.%(name)s.%(funcName)s]:%(lineno)s %(message)s",
    handlers=[
        logging.FileHandler("/log/debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
coloredlogs.install(
    level=os.getenv("LOG_LEVEL", "INFO"),
    fmt="%(asctime)s  [%(levelname)7s]  [%(module)s.%(name)s.%(funcName)s]:%(lineno)s %(message)s",
    logger=logger
)

ADMIN_SCOPE = ["audit:events_read"]

TEAMS_COMPLIANCE_SCOPE = ["spark-compliance:events_read",
    "spark-compliance:memberships_read", "spark-compliance:memberships_write",
    "spark-compliance:messages_read", "spark-compliance:messages_write",
    "spark-compliance:rooms_read", "spark-compliance:rooms_write",
    "spark-compliance:team_memberships_read", "spark-compliance:team_memberships_write",
    "spark-compliance:teams_read",
    "spark:people_read"] # "spark:rooms_read", "spark:kms"
    
TEAMS_COMPLIANCE_READ_SCOPE = ["spark-compliance:events_read",
    "spark-compliance:memberships_read",
    "spark-compliance:messages_read",
    "spark-compliance:rooms_read",
    "spark-compliance:team_memberships_read",
    "spark-compliance:teams_read",
    "spark:people_read"]

MEETINGS_COMPLIANCE_SCOPE = ["spark-compliance:meetings_write"]

DEFAULT_SCOPE = ["spark:kms"]

STATE_CHECK = "webex is great" # integrity test phrase
EVENT_CHECK_INTERVAL = 15 # seconds
EVENT_CHECK_DELAY = 60 # seconds, set the check interval window back in time to allow the event to be stored in Webex
SAFE_TOKEN_DELTA = 3600 # safety seconds before access token expires - renew if smaller

TIMESTAMP_KEY = "LAST_CHECK"

STORAGE_PATH = "/token_storage/data/"
WEBEX_TOKEN_FILE = "webex_tokens_{}.json"
TIMESTAMP_FILE = "timestamp_{}.json"

def sigterm_handler(_signo, _stack_frame):
    "When sysvinit sends the TERM signal, cleanup before exiting."

    logger.info("Received signal {}, exiting...".format(_signo))
    
    thread_executor._threads.clear()
    concurrent.futures.thread._threads_queues.clear()
    sys.exit(0)

signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)

thread_executor = concurrent.futures.ThreadPoolExecutor()
wxt_username = "COMPLIANCE"
wxt_token_key = "COMPLIANCE"
token_refreshed = False

options = {
    "wxt_compliance": False,
    "wxt_admin_audit": False,
    "wxt_resource": None,
    "wxt_type": None,
    "check_actor": False,
    "skip_timestamp": False
}

# statistics
statistics = {
    "started": datetime.utcnow(),
    "events": 0,
    "admin_events": 0,
    "max_time": 0,
    "max_time_at": datetime.now(),
    "resources": {},
    "admin": {}
}

class AccessTokenAbs(AccessToken):
    """
    Store Access Token with a real timestamp.
    
    Access Tokens are generated with 'expires-in' information. In order to store them
    it's better to have a real expiration date and time. Timestamps are saved in UTC.
    Note that Refresh Token expiration is not important. As long as it's being used
    to generate new Access Tokens, its validity is extended even beyond the original expiration date.
    
    Attributes:
        expires_at (float): When the access token expires
        refresh_token_expires_at (float): When the refresh token expires.
    """
    def __init__(self, access_token_json):
        super().__init__(access_token_json)
        if not "expires_at" in self._json_data.keys():
            self._json_data["expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.expires_in)).timestamp())
        logger.debug("Access Token expires in: {}s, at: {}".format(self.expires_in, self.expires_at))
        if not "refresh_token_expires_at" in self._json_data.keys():
            self._json_data["refresh_token_expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.refresh_token_expires_in)).timestamp())
        logger.debug("Refresh Token expires in: {}s, at: {}".format(self.refresh_token_expires_in, self.refresh_token_expires_at))
        
    @property
    def expires_at(self):
        return self._json_data["expires_at"]
        
    @property
    def refresh_token_expires_at(self):
        return self._json_data["refresh_token_expires_at"]

def save_tokens(token_key, tokens):
    """
    Save tokens.
    
    Parameters:
        tokens (AccessTokenAbs): Access & Refresh Token object
    """
    global token_refreshed
    
    logger.debug("AT timestamp: {}".format(tokens.expires_at))
    token_record = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at,
        "refresh_token_expires_at": tokens.refresh_token_expires_at
    }
    file_destination = get_webex_token_file(token_key)
    with open(file_destination, "w") as file:
        logger.debug("Saving Webex tokens to: {}".format(file_destination))
        json.dump(token_record, file)
    
    token_refreshed = True # indicate to the main loop that the Webex token has been refreshed
    
def get_webex_token_file(token_key):
    return STORAGE_PATH + WEBEX_TOKEN_FILE.format(token_key)
    
def get_tokens_for_key(token_key):
    """
    Load tokens.
    
    Parameters:
        token_key (str): A key to the storage of the token
        
    Returns:
        AccessTokenAbs: Access & Refresh Token object or None
    """
    try:
        file_source = get_webex_token_file(token_key)
        with open(file_source, "r") as file:
            logger.debug("Loading Webex tokens from: {}".format(file_source))
            token_data = json.load(file)
            tokens = AccessTokenAbs(token_data)
            return tokens
    except Exception as e:
        logger.info("Webex token load exception: {}".format(e))
        return None

def refresh_tokens_for_key(token_key):
    """
    Run the Webex 'get new token by using refresh token' operation.
    
    Get new Access Token. Note that the expiration of the Refresh Token is automatically
    extended no matter if it's indicated. So if this operation is run regularly within
    the time limits of the Refresh Token (typically 3 months), the Refresh Token never expires.
    
    Parameters:
        token_key (str): A key to the storage of the token
        
    Returns:
        str: message indicating the result of the operation
    """
    tokens = get_tokens_for_key(token_key)
    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
    integration_api = WebexTeamsAPI(access_token="12345")
    try:
        new_tokens = AccessTokenAbs(integration_api.access_tokens.refresh(client_id, client_secret, tokens.refresh_token).json_data)
        save_tokens(token_key, new_tokens)
        logger.info("Tokens refreshed for key {}".format(token_key))
    except ApiError as e:
        logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error refreshing an access token. Client Id and Secret loading error: {}".format(e)
        
    return "Tokens refreshed for {}".format(token_key)

def save_timestamp(timestamp_key, timestamp):
    """
    Save a timestamp.
    
    Parameters:
        timestamp_key (str): storage key for the timestamp
        timestamp (float): datetime timestamp
    """
    timestamp_destination = get_timestamp_file(timestamp_key)
    logger.debug("Saving timestamp to {}".format(timestamp_destination))
    with open(timestamp_destination, "w") as file:
        json.dump({"timestamp": timestamp}, file)
    
def load_timestamp(timestamp_key):
    """
    Save a timestamp.
    
    Parameters:
        timestamp_key (str): storage key for the timestamp
        
    Returns:
        float: timestamp for datetime
    """
    timestamp_source = get_timestamp_file(timestamp_key)
    logger.debug("Loading timestamp from {}".format(timestamp_source))
    try:
        with open(timestamp_source, "r") as file:
            ts = json.load(file)
            return float(ts.get("timestamp"))
    except Exception as e:
        logger.info("Timestamp load exception: {}".format(e))
        return None
            
def get_timestamp_file(timestamp_key):
    return STORAGE_PATH + TIMESTAMP_FILE.format(timestamp_key)
    
def load_config(options):
    """
    Load the configuration file.
    
    Returns:
        dict: configuration file JSON
    """
    with open("/config/config.json") as file:
        config = json.load(file)
    
    opt = config.get("options", {})
    for key, value in opt.items():
        options[key] = value
    return config
    
def secure_scheme(scheme):
    return re.sub(r"^http$", "https", scheme)

# Flask part of the code

"""
1. initialize database table if needed
2. start event checking thread
"""
@flask_app.before_first_request
def startup():
    logger.debug("Starting event check...")
    # check_events(EVENT_CHECK_INTERVAL, wxt_compliance, wxt_admin_audit, wxt_resource, wxt_type, wxt_actor_email)
    thread_executor.submit(check_events, EVENT_CHECK_INTERVAL)

@flask_app.route("/")
def hello():
    response = make_response(format_event_stats(), 200)
    response.mimetype = "text/plain"
    return response

"""
OAuth proccess done
"""
@flask_app.route("/authdone", methods=["GET"])
def authdone():
    ## TODO: post the information & help, maybe an event creation form to the 1-1 space with the user
    return "Thank you for providing the authorization. You may close this browser window."

"""
OAuth grant flow start
"""
@flask_app.route("/authorize", methods=["GET"])
def authorize():
    myUrlParts = urlparse(request.url)
    full_redirect_uri = os.getenv("REDIRECT_URI")
    if full_redirect_uri is None:
        full_redirect_uri = myUrlParts.scheme + "://" + myUrlParts.netloc + url_for("manager")
    logger.info("Authorize redirect URL: {}".format(full_redirect_uri))

    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    redirect_uri = quote(full_redirect_uri, safe="")
    scope = TEAMS_COMPLIANCE_READ_SCOPE + ADMIN_SCOPE + DEFAULT_SCOPE
    scope_uri = quote(" ".join(scope), safe="")
    join_url = webex_api.base_url+"authorize?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}".format(client_id, redirect_uri, scope_uri, STATE_CHECK)

    return redirect(join_url)
    
"""
OAuth grant flow redirect url
generate access and refresh tokens using "code" generated in OAuth grant flow
after user successfully authenticated to Webex

See: https://developer.webex.com/blog/real-world-walkthrough-of-building-an-oauth-webex-integration
https://developer.webex.com/docs/integrations
"""   
@flask_app.route("/manager", methods=["GET"])
def manager():
    global wxt_username
    
    if request.args.get("error"):
        return request.args.get("error_description")
        
    input_code = request.args.get("code")
    check_phrase = request.args.get("state")
    logger.debug("Authorization request \"state\": {}, code: {}".format(check_phrase, input_code))

    myUrlParts = urlparse(request.url)
    full_redirect_uri = os.getenv("REDIRECT_URI")
    if full_redirect_uri is None:
        full_redirect_uri = myUrlParts.scheme + "://" + myUrlParts.netloc + url_for("manager")
    logger.debug("Manager redirect URI: {}".format(full_redirect_uri))
    
    try:
        client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
        client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
        tokens = AccessTokenAbs(webex_api.access_tokens.get(client_id, client_secret, input_code, full_redirect_uri).json_data)
        logger.debug("Access info: {}".format(tokens))
    except ApiError as e:
        logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error issuing an access token. Client Id and Secret loading error: {}".format(e)
        
    webex_integration_api = WebexTeamsAPI(access_token=tokens.access_token)
    try:
        user_info = webex_integration_api.people.me()
        logger.debug("Got user info: {}".format(user_info))
        wxt_username = user_info.emails[0]
        save_tokens(wxt_token_key, tokens)
        
        ## TODO: add periodic access token refresh
    except ApiError as e:
        logger.error("Error getting user information: {}".format(e))
        return "Error getting your user information: {}".format(e)
        
    return redirect(url_for("authdone"))
    
# TODO: manual query of events API
@flask_app.route("/queryevents", methods=["GET"])
def query_events():
    results = ""
    
    return results

"""
Check events API thread. Infinite loop which periodically checks the Events API.
Doesn't work until "wxt_username" runs through OAuth grant flow above.
Access token is automatically refreshed if needed using Refresh Token.
No additional user authentication is required.
"""
def check_events(check_interval=EVENT_CHECK_INTERVAL):
    global token_refreshed, options, statistics
    
    tokens = None
    wxt_client = None
    
    xargs = {}
    if options["wxt_resource"] is not None:
        xargs["resource"] = options["wxt_resource"]
    if options["wxt_type"] is not None:
        xargs["type"] = options["wxt_type"]
    logger.debug("Additional args: {}".format(xargs))
    
    syslog_config = os.getenv("SYSLOG_SERVERS")
    syslog_server_list = syslog_config.replace(" ", "").split(",")

    syslog_list = []
    for syslog_server in syslog_server_list:
        syslog_list.append(create_syslog_client(syslog_server))
        
    syslog_facility = pysyslogclient.FAC_LOCAL0
    syslog_severity = pysyslogclient.SEV_INFO
    
    syslog_fac_config = os.getenv("SYSLOG_FACILITY")
    if syslog_fac_config:
        search_fac = "FAC_" + syslog_fac_config.upper()
        logger.debug("Searching facility: {}".format(search_fac))
        try:
            syslog_facility = getattr(pysyslogclient, search_fac)
        except AttributeError as e:
            logger.info("Facility not found: {}".format(e))
            
    syslog_sev_config = os.getenv("SYSLOG_SEVERITY")
    if syslog_sev_config:
        search_sev = "SEV_" + syslog_sev_config.upper()
        logger.debug("Searching severity: {}".format(search_sev))
        try:
            syslog_severity = getattr(pysyslogclient, search_sev)
        except AttributeError as e:
            logger.info("Severity not found: {}".format(e))
            
    logger.info("Syslog facility: {}, severity: {}".format(syslog_facility, syslog_severity))
    
    # check events from the last saved timestamp or from the application start
    if options["skip_timestamp"]:
        last_timestamp = None
    else:
        # load last timestamp from DB
        last_timestamp = load_timestamp(TIMESTAMP_KEY)
    
    if last_timestamp is None:
        from_time = datetime.utcnow() - timedelta(seconds = EVENT_CHECK_DELAY)
    else:
        from_time = datetime.fromtimestamp(last_timestamp)
        
    while True:
        try:
        # logger.debug("Check events tick.")

# check for token until there is one available in the DB        
            if tokens is None or token_refreshed:
                tokens = get_tokens_for_key(wxt_token_key)
                if tokens:
                    wxt_client = WebexTeamsAPI(access_token=tokens.access_token)

                    try:
                        user_info = wxt_client.people.me()
                        logger.debug("Got user info: {}".format(user_info))
                        wx_org_id = user_info.orgId
                    except ApiError as e:
                        logger.error("Me request error: {}".format(e))

                    token_refreshed = False
                else:
                    logger.error("No access tokens for key {}. Authorize the user first.".format(wxt_token_key))
                    
            if tokens:
        # renew access token using refresh token if needed
                # logger.info("tokens: {}".format(tokens))
                token_delta = datetime.fromtimestamp(float(tokens.expires_at)) - datetime.utcnow()
                if token_delta.total_seconds() < SAFE_TOKEN_DELTA:
                    logger.info("Access token is about to expire, renewing...")
                    refresh_tokens_for_key(wxt_token_key)
                    tokens = get_tokens_for_key(wxt_token_key)
                    wxt_client = WebexTeamsAPI(access_token=tokens.access_token)
                    new_client = True

            to_time = datetime.utcnow() - timedelta(seconds = EVENT_CHECK_DELAY)
        # query the Events API        
            if wxt_client:
                try:
                    from_stamp = from_time.isoformat(timespec="milliseconds")+"Z"
                    to_stamp = to_time.isoformat(timespec="milliseconds")+"Z"
                    logger.debug("check interval {} - {}".format(from_stamp, to_stamp))
                    config = load_config(options)
                    if options["wxt_compliance"]:
                        event_list = wxt_client.events.list(_from=from_stamp, to=to_stamp, **xargs)
                        for event in event_list:
                            handle_event(event, wxt_client, syslog_list, syslog_facility, syslog_severity, options, config)
                                                        
                    if options["wxt_admin_audit"]:
                        # get admin audit events
                        # logger.info("admin audit request, org id: {}".format(wx_org_id))
                        #
                        # the user who authorized the access needs to:
                        # 1. be Full Administrator (cannot be Read-Only Admin)
                        # 2. needs to login to admin.webex.com and accept the terms&conditions
                        #
                        admin_audit_list = wxt_client.admin_audit_events.list(wx_org_id, _from=from_stamp, to=to_stamp)
                        for event in admin_audit_list:
                            logger.debug(f"Admin audit event: {event}")
                            handle_admin_event(event, wxt_client, syslog_list, syslog_facility, syslog_severity, options, config)
                    from_time = to_time
                except ApiError as e:
                    logger.error("Admin audit API request error: {}".format(e))
                    
            # save timestamp
            save_timestamp(TIMESTAMP_KEY, to_time.timestamp())
            now_check = datetime.utcnow() - timedelta(seconds = EVENT_CHECK_DELAY)
            diff = (now_check - to_time).total_seconds()
            logger.info("event processing took {} seconds".format(diff))
            if diff > statistics["max_time"]:
                statistics["max_time"] = diff
                statistics["max_time_at"] = datetime.now()
            if diff < check_interval:
                time.sleep(check_interval - int(diff))
            else:
                logger.error("EVENT PROCESSING IS TAKING TOO LONG ({}), PERFORMANCE IMPROVEMENT NEEDED".format(diff))
        except Exception as e:
            logger.error("check_events() loop exception: {}".format(e))
            time.sleep(check_interval)
        finally:
            pass
            
def handle_event(event, wxt_client, syslog_list, syslog_facility, syslog_severity, options, config):
    """
    Handle Webex Events API query result
    """
    try:
        passed, actor = actor_passed(wxt_client, event.actorId, options, config)
        if not passed:
            return

        save_event_stats(event)

        event_data = event.json_data
        # logger.debug(f"event: {event_data}")
        try:
            event_data["data"].pop("text", None)
        except Exception as e:
            logger.debug(f"Pop exception: {e}")
        # syslog_msg = "WEBEX_COMPLIANCE {} {} {} {} by {} JSON: {}".format(event.created, event.resource, event.type, event.data.personEmail, actor.emails[0], json.dumps(event_data, separators=(",", ":")))
        syslog_msg = "{}: {}".format(actor.emails[0], json.dumps(event_data, separators=(",", ":")))
        # logger.info("{} {} {} {} by {}".format(event.created, event.resource, event.type, event.data.personEmail, actor.emails[0]))
        logger.info(f"syslog message: {syslog_msg}")
        send_syslog(syslog_list, syslog_msg, process_name = "WEBEXCOMPLIANCE", facility = syslog_facility, severity = syslog_severity)

    except Exception as e:
        logger.error("handle_event() exception: {}".format(e))
        
def handle_admin_event(admin_event, wxt_client, syslog_list, syslog_facility, syslog_severity, options, config):
    """
    Handle Webex Admin Audit Events API query result
    """
    try:
        passed, actor = actor_passed(wxt_client, admin_event.actorId, options, config)
        if not passed:
            return

        save_admin_event_stats(admin_event)

        audit_data = admin_event.data
        # syslog_msg = "WEBEX_ADMIN_AUDIT {} {} {} {} by {} JSON: {}".format(admin_event.created, audit_data.eventCategory, audit_data.eventDescription, audit_data.actionText, audit_data.actorEmail, json.dumps(admin_event.json_data))
        syslog_msg = "{}: {}".format(audit_data.actorEmail, json.dumps(admin_event.json_data["data"]))
        # logger.info("{} {} {} {} by {}".format(event.created, audit_data.eventCategory, audit_data.eventDescription, audit_data.actionText, audit_data.actorEmail))
        logger.info("admin audit event: {}".format(syslog_msg))
        send_syslog(syslog_list, syslog_msg, process_name = "WEBEXADMINAUDIT", facility = syslog_facility, severity = syslog_severity)
    except Exception as e:
        logger.error("handle_admin_event() exception: {}".format(e))

def actor_passed(wxt_client, actor_id, options, config):
    logger.debug(f"checking actor: {actor_id}")
    actor_id_decoded = base64.b64decode(actor_id + '=' * (-len(actor_id) % 4))
    actor_uuid = actor_id_decoded.decode("ascii").split("/")[-1] # uuid is the last element of actor id
    logger.debug(f"actor uuid: {actor_uuid}")
    full_actor_id = base64.b64encode(f"ciscospark://us/PEOPLE/{actor_uuid}".encode("ascii")).decode("ascii").rstrip("=")
    logger.debug(f"actor id: {full_actor_id}")
    actor = wxt_client.people.get(full_actor_id)

    if options["check_actor"]:

        actor_list = config.get("actors")
        logger.debug("configured actors: {}".format(actor_list))
        if not any(actor.emails[0].lower() in act_member.lower() for act_member in actor_list):
            logger.info("{} ({}) not in configured actor list".format(actor.displayName, actor.emails[0]))
            return False, actor
    
    return True, actor
            
def create_syslog_client(syslog_cfg):
    match = re.match(r"(.*):(.*)/(tcp|udp)", syslog_cfg) # hostname:port/protocol
    protocol = "UDP"
    port = "514"
    destination = None
    if match is None:
        match = re.match(r"(.*):(.*)", syslog_cfg) # hostname:port
        if match:
            destination = match.group(1)
            port = match.group(2)
        else:
            destination = syslog_cfg # hostname
    else:
        destination = match.group(1)
        port = match.group(2)
        protocol = match.group(3).upper()
        
    logger.info("Creating syslog client {}:{}/{}".format(destination, port, protocol))
    # return pysyslogclient.SyslogClientRFC5424(destination, port, proto = protocol)
    return pysyslogclient.SyslogClientRFC3164(destination, port, proto = protocol)

def send_syslog(syslog_client_list, message, process_name = None, facility = pysyslogclient.FAC_LOCAL0, severity = pysyslogclient.SEV_INFO):
    if process_name is None:
        progname = os.path.basename(inspect.stack()[-1].filename)
        process_name = os.path.splitext(progname)[0]
    for syslog_client in syslog_client_list:
        syslog_client.log(message, facility = facility, severity = severity, program = process_name)

def save_event_stats(event):
    """
    Save statistics
    
    Saves statistics to a "statistics" singleton
    
    Parameters:
        event (Event): Event API response object
    """
    global statistics
    
    statistics["events"] += 1
    counter_ref = statistics["resources"].get(event.resource)
    if counter_ref is None:
        statistics["resources"][event.resource] = {}
        counter = 0
    else:
        counter = counter_ref.get(event.type, 0)
    counter += 1
    logger.debug("save_event_stats() counter for {}/{} is now: {}".format(event.resource, event.type, counter))
    statistics["resources"][event.resource][event.type] = counter
    
def save_admin_event_stats(admin_event):
    """
    Save statistics
    
    Saves statistics to a "statistics" singleton
    
    Parameters:
        admin_event (Event): Admin Event API response object
    """
    global statistics
    
    event_category = admin_event.data.eventCategory
    event_type = admin_event.data.targetType
    logger.debug(f"Admin event {event_category}/{event_type}")
    statistics["admin_events"] += 1
    counter_ref = statistics["admin"].get(event_category)
    if counter_ref is None:
        statistics["admin"][event_category] = {}
        counter = 0
    else:
        counter = counter_ref.get(event_type, 0)
    counter += 1
    logger.debug("save_admin_event_stats() counter for {}/{} is now: {}".format(event_category, event_type, counter))
    statistics["admin"][event_category][event_type] = counter
    
def format_event_stats():
    """
    Format event statistics for print
    
    Returns:
        str: formatted statistics
    """
    global statistics
    
    res_str = "User events\n"
    for res_key, res_value in statistics["resources"].items():
        res_str += "{}:\n".format(res_key)
        for type_key, type_value in statistics["resources"][res_key].items():
            res_str += "{:<4}{:>14}:{:8d}\n".format("", type_key, type_value)
    
    res_str += "\nAdmin audit events\n"
    for res_key, res_value in statistics["admin"].items():
        res_str += "{}:\n".format(res_key)
        for type_key, type_value in statistics["admin"][res_key].items():
            res_str += "{:<4}{:>14}:{:8d}\n".format("", type_key, type_value)

    start_time = "{:%Y-%m-%d %H:%M:%S GMT}".format(statistics["started"])
    max_timestamp = "{:%Y-%m-%d %H:%M:%S}".format(statistics["max_time_at"])
    now = datetime.utcnow()
    time_diff = now - statistics["started"]
    hours, remainder = divmod(time_diff.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    diff_time = "{}d {:02d}:{:02d}:{:02d}".format(time_diff.days, int(hours), int(minutes), int(seconds))
    result = """Webex to SIEM Logger

Started: {}
Up: {}

Event statistics
Total user events: {}
Total admin events: {}
Maximum processing time: {:0.2f}s at {}
{}
""".format(start_time, diff_time, statistics["events"], statistics["admin_events"], statistics["max_time"], max_timestamp, res_str)
    
    return result

"""
Independent thread startup, see:
https://networklore.com/start-task-with-flask/
"""
def start_runner():
    def start_loop():
        no_proxies = {
          "http": None,
          "https": None,
        }
        not_started = True
        while not_started:
            logger.info('In start loop')
            try:
                r = requests.get('https://127.0.0.1:5050/', proxies=no_proxies, verify=False)
                if r.status_code == 200:
                    logger.info('Server started, quiting start_loop')
                    not_started = False
                else:
                    logger.debug("Status code: {}".format(r.status_code))
            except Exception as e:
                logger.info(f'Server not yet started: {e}')
            time.sleep(2)

    logger.info('Started runner')
    thread_executor.submit(start_loop)


if __name__ == "__main__":
    import argparse
    
    # default_user = os.getenv("COMPLIANCE_USER")
    # if default_user is None:
    #     default_user = os.getenv("COMPLIANCE_USER_DEFAULT")
    #     if default_user is None:
    #         default_user = "COMPLIANCE"
    # 
    # logger.info("Compliance user from env variables: {}".format(default_user))

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='count', help="Set logging level by number of -v's, -v=WARN, -vv=INFO, -vvv=DEBUG")
    parser.add_argument("-c", "--compliance", action='store_true', help="Monitor compliance events, default: no")
    parser.add_argument("-m", "--admin", action='store_true', help="Monitor admin audit events, default: no")
    parser.add_argument("-r", "--resource", type = str, help="Resource type (messages, memberships), default: all")
    parser.add_argument("-t", "--type", type = str, help="Event type (created, updated, deleted), default: all")
    parser.add_argument("-a", "--check_actor", action='store_true', help="Perform actions only if the Webex Event actor is in the \"actors\" list from the /config/config.json file, default: no")
    parser.add_argument("-s", "--skip_timestamp", action='store_true', help="Ignore stored timestamp and monitor the events just from the application start, default: no")
    
    args = parser.parse_args()
    if args.verbose:
        if args.verbose > 2:
            logging.basicConfig(level=logging.DEBUG)
        elif args.verbose > 1:
            logging.basicConfig(level=logging.INFO)
        if args.verbose > 0:
            logging.basicConfig(level=logging.WARN)
            
    logger.info("Logging level: {}".format(logging.getLogger(__name__).getEffectiveLevel()))
    
    options["wxt_compliance"] = args.compliance
    options["wxt_admin_audit"] = args.admin
    options["wxt_resource"] = args.resource
    options["wxt_type"] = args.type
    options["check_actor"] = args.check_actor
    options["skip_timestamp"] = args.skip_timestamp
        
    config = load_config(options)

    logger.info("OPTIONS: {}".format(options))
    logger.info("CONFIG: {}".format(config))

    start_runner()
    flask_app.run(host="0.0.0.0", port=5050, ssl_context='adhoc')
