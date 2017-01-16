import flask
from flask import Flask, url_for, render_template, redirect, request
from flask import session as login_session
import urllib
import requests

from datetime import datetime, timedelta
import dateutil.parser
# import parsedatetime.parsedatetime
import random
import string
import json
import os
from flask import send_from_directory


### NEEDED TO USE BOOTSTRAP'S TEMPLATES  ###
from flask_bootstrap import Bootstrap

def create_app():
  app = Flask(__name__)
  Bootstrap(app)
  return app

app = Flask(__name__)




### KEYS ###
CLIENT_ID = '0fWSJQbzHQVFFGzfxd5TJzz8nm2mdWGGL9QlsYxP'
CLIENT_SECRET = 'fPJK1pCU56QvbRl8AxrvfBarGf5zOgw1M9BqnYgt5zBmdiEn2A'
API_KEY = ''
REDIRECT_URI = 'http://localhost:5001/callback'

### AS I RECEIVED A WARNING OF LACK OF FAVICON, I CREATE ONE AND PUT IN THE PATH ###

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')


def auth_url():
    url = "http://localhost:5000/api/authorize"

    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'all',
        'access_type': 'offline',
        'approval_prompt': 'force'
    }
    return "{0}?{1}".format(url, urllib.urlencode(params))


### BUILD THE TOKEN WITH RECEIVED CODE ###
# def code_for_token(code):
#     print "code_for_token recibido: "
#     print code
#     url = "http://localhost:5000/api/token"
#     data = {'key1': 'data1', 'key2': 'data2'}
#     headers = {'content-type': 'application/json'}
#
#     r = requests.post(url, data=json.dumps(data), headers=headers)
#     results = json.loads(r.text)
#     access_token = results['access_token']
#     refresh_token = results['refresh_token']
#     print "access_token recibido es:"
#     print access_token
#     return (access_token, refresh_token)

def code_for_token(code):
    print "code_for_token recibido: "
    print code
    headers = {'content-type': 'application/json'}
    url = "http://localhost:5000/api/token"
    params = {
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    #params = {'key1': 'code',
    #          'key2': 'data2'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)

    access_token = results['access_token']
    refresh_token = results['refresh_token']
    expires_in = results['expires_in']
    expires = results['expires']
    print "en token expires vale"
    print expires
    return (access_token, refresh_token,expires_in, expires)

### AUTH BUT WITHOUT THE NEED TO RE-AUTH ###
def refresh_token(refresh_token):
    url = "https://accounts.google.com/o/oauth2/token"
    params = {
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token'
    }
    r = requests.post(url, data=params)
    results = json.loads(r.text)
    return results['access_token']

def get_profile(access_token):
    url = "http://localhost:5000/api/me"
    params = {'access_token': access_token}
    r = requests.get(url, params=params)
    return json.loads(r.text)


# def get_email(access_token):
#    url = "https://www.googleapis.com/calendar/v3/users/me/calendarList"
#    params = {'access_token': access_token}
#    r = requests.get(url, params=params)
#    result = json.loads(r.text)
#    cals = []
#    for item in result['items']:
#        cal = {'id': item['id'], 'active': False}
#        if 'summaryOverride' in item:
#            cal['name'] = item['summaryOverride']
#        else:
#            cal['name'] = item['summary']
#        cals.append(cal)
#    return cals[0]['id']


#def get_todays_events(access_token, cal_id, date=None):
#    url = "https://www.googleapis.com/calendar/v3/calendars/{0}/events"
#    url = url.format(urllib.quote_plus(cal_id))
#    day = datetime.datetime.now() if date is None else date
#    params = {
#        'access_token': access_token,
#        'orderBy': 'startTime',
#        'singleEvents': 'true',
#       'timeMin': day.strftime("%Y-%m-%dT00:00:00Z"),
#        'timeMax': day.strftime("%Y-%m-%dT23:59:59Z")
#    }
#    url = "{0}?{1}".format(url, urllib.urlencode(params))
#    r = urllib.urlopen(url)
#    results = json.loads(r.read())
#    events = []
#    if 'items' not in results:
#        return events
#    for item in results['items']:
#        if 'date' in item['start']:
#            time = -1
#        else:
#            start = dateutil.parser.parse(item['start']['dateTime'])
#            if start.minute == 0:
#                time = start.strftime("%H")
#            else:
#                time = start.strftime("%H.%M")
#        name = item['summary']
#        events.append((time, name))
#    return events

#def events_to_texts(events, header=''):
#    print "enventos"
#    print events
#    if events==[]:
#        events=[('12', u'Free day!!!')]
#    events = ["{0}: {1}".format(*e) if e[0] != -1 else e[1] for e in events]
#    build = "{0}{1}".format(header, events[0])
#    texts = []
#    for event in events[1:]:
#        if len(build) + len(event) > 158:
#            texts.append(build)
#            build = event
#        else:
#            build += ", {0}".format(event)
#    return texts + [build]

#def texts_for_user(access_token, user,  date=None, header=''):
#    user_events = []
#    user_events += get_todays_events(access_token, user, date)
#    user_events.sort()
#    return events_to_texts(user_events, header)

### HOMEPAGE FOR ACCESSING GOOGLE'S SERVICES ###
@app.route('/')
def index():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return flask.render_template('store.html', url=auth_url())
    #return flask.render_template('client/login_with_registration.html')


#@app.route('/processing', methods=['POST'])
#def loging():
#    usuario = request.form['username']
#    contrasenia = request.form['password']
#    print "nombre"
#    print usuario
#    print "contrasenia"
#    print contrasenia
#    return 1


@app.route('/logout')
def logout():
    login_session.clear()
    return redirect(url_for("index"))

####    WHEN RECEIVE ANSWER, I CATCH CODE FOR BUILD TOKEN

@app.route('/callback')
def callback():
    ### WE CATCH RECEIVED ARGUMENTS (IT'S A STRING CALLED "CODE")
    args = flask.request.args
    if args.get('error', None):
        return "Authentication error: {0}".format(args['error'])
    code = args.get('code', None)
    if not code:
        return "Authentication error: no code provided"
    print "args"
    print args
    print "code"
    print code
    tokens = code_for_token(code)
    acc_token = tokens[0]
    ref_token = tokens[1]
    expira = tokens[3]
    ahora = datetime.now() + timedelta(seconds=0)
    print "expira"
    print expira
    print "ahora"
    print ahora
    #if expira > ahora:
    #    estado="valido"
    #else:
    estado = "vencido"
    ### WE RECEIVE TODAY'S TASK FROMS CALENDAR "MAIL_ADDRESS"
   # cadena=texts_for_user(tokens[0],mail_adress)
    #print "tareas"
    #print cadena[0]
    ### THEN PRINT NAME, PICTURE AND TODAY'S TASKS
    #return render_template("inicio.html", USERNAME=profile['name'],PHOTO_URL=profile['picture'],TAREAS=cadena[0])
    return render_template("indexcli.html", WHO='luciano', STATUS=estado, EXPIRES=expira)

if __name__ == '__main__':
    app.secret_key = 'twtrtretrefsdgfgvbcvbbvbcviutiujgkhj'
    app.run(host='127.0.0.1', port=5001, use_reloader=False)
