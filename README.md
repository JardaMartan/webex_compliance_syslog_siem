# Webex Teams Compliance (Events) API Sample Client

This is a sample implementation of [Compliance](https://developer.webex.com/docs/api/guides/compliance) monitoring of Webex Teams [Events API](https://developer.webex.com/docs/api/v1/events). It periodically checks for new events (EVENT_CHECK_INTERVAL, default 15s) and logs the data. The application is using OAuth grant flow to get the access token. So it can be used also as a sample of [Webex Teams Integration](https://developer.webex.com/docs/integrations) implementation. Because the application implements the OAuth grant flow, it runs a web server using [Flask](https://flask.palletsprojects.com). In order to avoid running the OAuth flow at every start, the Access and Refresh Tokens are stored in a database. The application is using standalone [DynamoDB](https://hub.docker.com/r/amazon/dynamodb-local) running in Docker container.

## How to run it
1. **Create a new Webex Teams integration**
  * login to https://developer.webex.com
  * click on your avatar in the upper right corner and select **[My Webex Apps](https://developer.webex.com/my-apps)**
  * click on **[Create New App](https://developer.webex.com/my-apps/new)** and select **Create an Integration**
  * set the **Redirect URI** to `http://localhost:5050/manager`
  * fill in the required fields and select Scopes `spark:people_read` and all that start with `spark-compliance` (`spark-compliance:events_read`, `spark-compliance:memberships_write`, etc.)
  * click **Save**
  * create a copy of `.env_sample` (for example `.env_local`)
  * copy & paste **Integration ID**, **Client ID** and **Client Secret** to the appropriate variables in `.env_local` (WEBEX_INTEGRATION_ID, WEBEX_INTEGRATION_CLIENT_ID, WEBEX_INTEGRATION_CLIENT_SECRET). Save the file.
2. **Create Compliance Officer account**
  * login to [Webex Control Hub](https://admin.webex.com) and select a user who will act as a Compliance Officer (or create a new user).
  * in the **Roles and Security** click on **Service Access** and check the **Compliance Officer** checkbox
  * click **Save**
3. **Start the database docker container** `docker run -p 8000:8000 amazon/dynamodb-local`
4. **Prepare Python3 virtual environment**
  * run command `python3 -m venv venv`
  * import required packages `pip install -r requirements.txt`
  * activate the virtual environment `source venv/bin/activate`
5. **Run the application script** `dotenv -f .env_local run python wxt_compliance.py -u compliance_officer@email.address` where `compliance_officer@email.address` is the e-mail address of Compliance Officer created in previous step.
6. Because you have not ran the OAuth grant flow yet, the application will log `ERROR:wxt_compliance:No access tokens for user compliance_officer@email.address. Authorize the user first.`
7. Open `http://localhost:5050/authorize`
8. If you have done the previous steps correctly, you will be asked to login to Webex. Use the Compliance Officer credentials. After logging in, confirm the scopes required by the application. At the end of the OAuth process you will be redirected to http://localhost:5050/authdone and presented with a message "**Thank you for providing the authorization. You may close this browser window.**"
9. In the application log you will see the Access and Refresh Tokens being created and saved in DynamoDB.
10. The application will start monitoring the Events API.
11. Try sending a message in Webex Teams, creating s Space or adding/deleting users to a Space. All should be logged by the application.
12. If you want to monitor only certain type of events, stop the application using Ctrl-C and add `--resource` or `--type` parameters with appropriate values. You can also monitor only certain person's activites by setting `--actor` parameter (person's e-mail address).
