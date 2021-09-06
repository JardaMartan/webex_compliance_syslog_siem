#!/bin/#!/usr/bin/env python3

import os
import sys
import uuid
import logging
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from urllib.parse import urlparse, quote

from webexteamssdk import WebexTeamsAPI, ApiError, AccessToken
webex_api = WebexTeamsAPI(access_token="12345")

import boto3
from ddb_single_table_obj import DDB_Single_Table

import json, requests
from datetime import datetime, timedelta, timezone
import time
from flask import Flask, request, redirect, url_for

import re
import pysyslogclient

import concurrent.futures
import signal

flask_app = Flask(__name__)
flask_app.config["DEBUG"] = True
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger()

ddb = None

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
EVENT_CHECK_INTERVAL = 15
SAFE_TOKEN_DELTA = 3600 # safety seconds before access token expires - renew if smaller

TIMESTAMP_KEY = "LAST_CHECK"

def sigterm_handler(_signo, _stack_frame):
    "When sysvinit sends the TERM signal, cleanup before exiting."

    flask_app.logger.info("Received signal {}, exiting...".format(_signo))
    
    thread_executor._threads.clear()
    concurrent.futures.thread._threads_queues.clear()
    sys.exit(0)

signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)

thread_executor = concurrent.futures.ThreadPoolExecutor()
wxt_username = "COMPLIANCE"
wxt_token_key = "COMPLIANCE"
wxt_resource = None
wxt_type = None
wxt_actor_email = None
wxt_admin_audit = False
wxt_compliance = False
token_refreshed = False

class AccessTokenAbs(AccessToken):
    def __init__(self, access_token_json):
        super().__init__(access_token_json)
        if not "expires_at" in self._json_data.keys():
            self._json_data["expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.expires_in)).timestamp())
        flask_app.logger.debug("Access Token expires in: {}s, at: {}".format(self.expires_in, self.expires_at))
        if not "refresh_token_expires_at" in self._json_data.keys():
            self._json_data["refresh_token_expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.refresh_token_expires_in)).timestamp())
        flask_app.logger.debug("Refresh Token expires in: {}s, at: {}".format(self.refresh_token_expires_in, self.refresh_token_expires_at))
        
    @property
    def expires_at(self):
        return self._json_data["expires_at"]
        
    @property
    def refresh_token_expires_at(self):
        return self._json_data["refresh_token_expires_at"]

def save_tokens(token_key, tokens):
    global token_refreshed
    
    flask_app.logger.debug("AT timestamp: {}".format(tokens.expires_at))
    token_record = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at,
        "refresh_token_expires_at": tokens.refresh_token_expires_at
    }
    ddb.save_db_record(token_key, "TOKENS", str(tokens.expires_at), **token_record)
    
    token_refreshed = True
    
def get_tokens_for_key(token_key):
    db_tokens = ddb.get_db_record(token_key, "TOKENS")
    flask_app.logger.debug("Loaded tokens from db: {}".format(db_tokens))
    
    if db_tokens:
        tokens = AccessTokenAbs(db_tokens)
        flask_app.logger.debug("Got tokens: {}".format(tokens))
        return tokens
    else:
        flask_app.logger.error("No tokens for key {}.".format(token_key))
        return None

def refresh_tokens_for_key(token_key):
    tokens = get_tokens_for_key(token_key)
    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
    integration_api = WebexTeamsAPI()
    try:
        new_tokens = AccessTokenAbs(integration_api.access_tokens.refresh(client_id, client_secret, tokens.refresh_token).json_data)
        save_tokens(token_key, new_tokens)
        flask_app.logger.info("Tokens refreshed for key {}".format(token_key))
    except ApiError as e:
        flask_app.logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error refreshing an access token. Client Id and Secret loading error: {}".format(e)
        
    return "Tokens refreshed for {}".format(token_key)
    
def save_timestamp(timestamp_key, timestamp):
    ddb.save_db_record(timestamp_key, "TIMESTAMP", str(timestamp))
    
def load_timestamp(timestamp_key):
    db_timestamp = ddb.get_db_record(timestamp_key, "TIMESTAMP")
    flask_app.logger.debug("Loaded timestamp from db: {}".format(db_timestamp))
    
    try:
        res = float(db_timestamp["pvalue"])
        return res
    except Exception as e:
        flask_app.logger.debug("timestamp exception: {}".format(e))
        return None

# Flask part of the code

"""
1. initialize database table if needed
2. start event checking thread
"""
@flask_app.before_first_request
def startup():
    global ddb
    
    ddb = DDB_Single_Table()
    flask_app.logger.debug("initialize DDB object {}".format(ddb))
        
    flask_app.logger.debug("Starting event check...")
    # check_events(EVENT_CHECK_INTERVAL, wxt_compliance, wxt_admin_audit, wxt_resource, wxt_type, wxt_actor_email)
    thread_executor.submit(check_events, EVENT_CHECK_INTERVAL, wxt_compliance, wxt_admin_audit, wxt_resource, wxt_type, wxt_actor_email)

@flask_app.route("/")
def hello():
    return "Hello World!"

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
    flask_app.logger.info("Authorize redirect URL: {}".format(full_redirect_uri))

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
    flask_app.logger.debug("Authorization request \"state\": {}, code: {}".format(check_phrase, input_code))

    myUrlParts = urlparse(request.url)
    full_redirect_uri = os.getenv("REDIRECT_URI")
    if full_redirect_uri is None:
        full_redirect_uri = myUrlParts.scheme + "://" + myUrlParts.netloc + url_for("manager")
    flask_app.logger.debug("Manager redirect URI: {}".format(full_redirect_uri))
    
    try:
        client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
        client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
        tokens = AccessTokenAbs(webex_api.access_tokens.get(client_id, client_secret, input_code, full_redirect_uri).json_data)
        flask_app.logger.debug("Access info: {}".format(tokens))
    except ApiError as e:
        flask_app.logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error issuing an access token. Client Id and Secret loading error: {}".format(e)
        
    webex_integration_api = WebexTeamsAPI(access_token=tokens.access_token)
    try:
        user_info = webex_integration_api.people.me()
        flask_app.logger.debug("Got user info: {}".format(user_info))
        wxt_username = user_info.emails[0]
        save_tokens(wxt_token_key, tokens)
        
        ## TODO: add periodic access token refresh
    except ApiError as e:
        flask_app.logger.error("Error getting user information: {}".format(e))
        return "Error getting your user information: {}".format(e)
        
    return redirect(url_for("authdone"))
    
"""
Manual token refresh of a single user. Not needed if the thread is running.
"""
@flask_app.route("/tokenrefresh", methods=["GET"])
def token_refresh():
    token_key = request.args.get("token_key")
    if token_key is None:
        return "Please provide a user id"
    
    return refresh_tokens_for_key(token_key)
    
"""
Manual token refresh of all users. Not needed if the thread is running.
"""
@flask_app.route("/tokenrefreshall", methods=["GET"])
def token_refresh_all():
    results = ""
    user_tokens = ddb.get_db_record_by_secondary_key("TOKENS")
    for token in user_tokens:
        flask_app.logger.debug("Refreshing: {} token".format(token["pk"]))
        results += refresh_tokens_for_key(token["pk"])+"\n"
    
    return results

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
def check_events(check_interval=EVENT_CHECK_INTERVAL, wx_compliance=False, wx_admin_audit=False, wx_resource=None, wx_type=None, wx_actor_email=None):
    global token_refreshed
    
    tokens = None
    wxt_client = None
    
    xargs = {}
    if wx_resource is not None:
        xargs["resource"] = wx_resource
    if wx_type is not None:
        xargs["type"] = wx_type
    flask_app.logger.debug("Additional args: {}".format(xargs))
    
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
        flask_app.logger.debug("Searching facility: {}".format(search_fac))
        try:
            syslog_facility = getattr(pysyslogclient, search_fac)
        except AttributeError as e:
            flask_app.logger.info("Facility not found: {}".format(e))
            
    syslog_sev_config = os.getenv("SYSLOG_SEVERITY")
    if syslog_sev_config:
        search_sev = "SEV_" + syslog_sev_config.upper()
        flask_app.logger.debug("Searching severity: {}".format(search_sev))
        try:
            syslog_severity = getattr(pysyslogclient, search_sev)
        except AttributeError as e:
            flask_app.logger.info("Severity not found: {}".format(e))
            
    flask_app.logger.info("Syslog facility: {}, severity: {}".format(syslog_facility, syslog_severity))
    
    # load last timestamp from DB
    last_timestamp = load_timestamp(TIMESTAMP_KEY)
    
    if last_timestamp is None:
        from_time = datetime.utcnow()
    else:
        from_time = datetime.fromtimestamp(last_timestamp)
        
    while True:
        try:
        # flask_app.logger.debug("Check events tick.")

# check for token until there is one available in the DB        
            if tokens is None or token_refreshed:
                tokens = get_tokens_for_key(wxt_token_key)
                if tokens:
                    wxt_client = WebexTeamsAPI(access_token=tokens.access_token)

        # get actorId if required
                    if wx_actor_email is not None:
                        try:
                            wx_actor_list = wxt_client.people.list(email=wx_actor_email)
                            for person in wx_actor_list:
                                xargs["actorId"] = person.id
                        except ApiError as e:
                            flask_app.logger.error("People list API request error: {}".format(e))
                    
                    try:
                        user_info = wxt_client.people.me()
                        flask_app.logger.debug("Got user info: {}".format(user_info))
                        wx_org_id = user_info.orgId
                    except ApiError as e:
                        flask_app.logger.error("Me request error: {}".format(e))

                    token_refreshed = False
                else:
                    flask_app.logger.error("No access tokens for key {}. Authorize the user first.".format(wxt_token_key))
                    
            if tokens:
        # renew access token using refresh token if needed
                # flask_app.logger.info("tokens: {}".format(tokens))
                token_delta = datetime.fromtimestamp(float(tokens.expires_at)) - datetime.utcnow()
                if token_delta.total_seconds() < SAFE_TOKEN_DELTA:
                    flask_app.logger.info("Access token is about to expire, renewing...")
                    refresh_tokens_for_key(wxt_token_key)
                    tokens = get_tokens_for_key(wxt_token_key)
                    wxt_client = WebexTeamsAPI(access_token=tokens.access_token)
                    new_client = True

        # query the Events API        
            if wxt_client:
                try:
                    to_time = datetime.utcnow()
                    from_stamp = from_time.isoformat(timespec="milliseconds")+"Z"
                    to_stamp = to_time.isoformat(timespec="milliseconds")+"Z"
                    flask_app.logger.debug("check interval {} - {}".format(from_stamp, to_stamp))
                    if wx_compliance:
                        event_list = wxt_client.events.list(_from=from_stamp, to=to_stamp, **xargs)
                        for event in event_list:
                            actor = wxt_client.people.get(event.actorId)
                            
                            # TODO: information logging to an external system
                            syslog_msg = "{} {} {} {} by {} JSON: {}".format(event.created, event.resource, event.type, event.data.personEmail, actor.emails[0], json.dumps(event.json_data))
                            flask_app.logger.info("{} {} {} {} by {}".format(event.created, event.resource, event.type, event.data.personEmail, actor.emails[0]))
                            send_syslog(syslog_list, syslog_msg, facility = syslog_facility, severity = syslog_severity)
                            
                    if wx_admin_audit:
                        # get admin audit events
                        # flask_app.logger.info("admin audit request, org id: {}".format(wx_org_id))
                        #
                        # the user who authorized the access needs to:
                        # 1. be Full Administrator (cannot be Read-Only Admin)
                        # 2. needs to login to admin.webex.com and accept the terms&conditions
                        #
                        admin_audit_list = wxt_client.admin_audit_events.list(wx_org_id, _from=from_stamp, to=to_stamp)
                        for event in admin_audit_list:
                            # TODO: information logging to an external system
                            audit_data = event.data
                            syslog_msg = "{} {} {} {} by {} JSON: {}".format(event.created, audit_data.eventCategory, audit_data.eventDescription, audit_data.actionText, audit_data.actorEmail, json.dumps(event.json_data))
                            # flask_app.logger.info("{} {} {} {} by {}".format(event.created, audit_data.eventCategory, audit_data.eventDescription, audit_data.actionText, audit_data.actorEmail))
                            flask_app.logger.info("admin audit event: {}".format(syslog_msg))
                            send_syslog(syslog_list, syslog_msg, facility = syslog_facility, severity = syslog_severity)
                    from_time = to_time
                except ApiError as e:
                    flask_app.logger.error("Admin audit API request error: {}".format(e))
                    
        except Exception as e:
            flask_app.logger.error("Loop excepion: {}".format(e))        

        finally:
            # save timestamp
            save_timestamp(TIMESTAMP_KEY, to_time.timestamp())
            time.sleep(check_interval)
        
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
        
    flask_app.logger.info("Creating syslog client {}:{}/{}".format(destination, port, protocol))
    return pysyslogclient.SyslogClientRFC5424(destination, port, proto = protocol)

def send_syslog(syslog_client_list, message, facility = pysyslogclient.FAC_LOCAL0, severity = pysyslogclient.SEV_INFO):
    for syslog_client in syslog_client_list:
        syslog_client.log(message, facility = facility, severity = severity)

"""
Independent thread startup, see:
https://networklore.com/start-task-with-flask/
"""
def start_runner():
    def start_loop():
        not_started = True
        while not_started:
            logger.info('In start loop')
            try:
                r = requests.get('http://127.0.0.1:5050/')
                if r.status_code == 200:
                    logger.info('Server started, quiting start_loop')
                    not_started = False
                logger.debug("Status code: {}".format(r.status_code))
            except:
                logger.info('Server not yet started')
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
    # flask_app.logger.info("Compliance user from env variables: {}".format(default_user))

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='count', help="Set logging level by number of -v's, -v=WARN, -vv=INFO, -vvv=DEBUG")
    parser.add_argument("-c", "--compliance", action='store_true', help="Monitor compliance events, default: no")
    parser.add_argument("-m", "--admin", action='store_true', help="Monitor admin audit events, default: no")
    # parser.add_argument("-u", "--username", type = str, help="Compliance Officer username (e-mail)", default=default_user)
    parser.add_argument("-r", "--resource", type = str, help="Resource type (messages, memberships), default: all")
    parser.add_argument("-t", "--type", type = str, help="Event type (created, updated, deleted), default: all")
    parser.add_argument("-a", "--actor", type = str, help="Monitored actor id (user's e-mail), default: all")
    
    args = parser.parse_args()
    if args.verbose:
        if args.verbose > 2:
            logging.basicConfig(level=logging.DEBUG)
        elif args.verbose > 1:
            logging.basicConfig(level=logging.INFO)
        if args.verbose > 0:
            logging.basicConfig(level=logging.WARN)
            
    flask_app.logger.info("Logging level: {}".format(logging.getLogger(__name__).getEffectiveLevel()))
    
    flask_app.logger.info("Using database: {} - {}".format(os.getenv("DYNAMODB_ENDPOINT_URL"), os.getenv("DYNAMODB_TABLE_NAME")))
    
    wxt_compliance = args.compliance
    wxt_admin_audit = args.admin
    wxt_resource = args.resource
    wxt_type = args.type
    wxt_actor_email = args.actor
    # wxt_username = args.username
        
    start_runner()
    flask_app.run(host="0.0.0.0", port=5050)
