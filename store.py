import flask
from flask import Flask, url_for, render_template, redirect, request
from flask import session as login_session
import urllib
import requests
import dateutil.parser
import random
import string
import json
import os
from flask import send_from_directory
from datetime import datetime, timedelta




############################################################################################################
### NEEDED TO USE BOOTSTRAP'S TEMPLATES  ###
from flask_bootstrap import Bootstrap

def create_app():
  app = Flask(__name__)
  Bootstrap(app)
  return app

app = Flask(__name__)


############################################################################################################
from math import ceil


class Pagination(object):

    def __init__(self, page, per_page, total_count):
        self.page = page
        self.per_page = per_page
        self.total_count = total_count

    @property
    def pages(self):
        return int(ceil(self.total_count / float(self.per_page)))

    @property
    def has_prev(self):
        return self.page > 1

    @property
    def has_next(self):
        return self.page < self.pages

    def iter_pages(self, left_edge=2, left_current=2,
                   right_current=5, right_edge=2):
        last = 0
        for num in xrange(1, self.pages + 1):
            if num <= left_edge or \
               (num > self.page - left_current - 1 and \
                num < self.page + right_current) or \
               num > self.pages - right_edge:
                if last + 1 != num:
                    yield None
                yield num
                last = num

def url_for_other_page(page):
    args = request.view_args.copy()
    args['page'] = page
    return url_for(request.endpoint, **args)
app.jinja_env.globals['url_for_other_page'] = url_for_other_page



CLIENT_ID = 'lSu13yAiv5DIF8YcpfNQw0ucXu9rcOxpzvShhjDx' #luciano
CLIENT_SECRET = 'GVAGTgrlf0TkhSljOzqrtYw58tiAOKhdK3KvYuLmtRXFyPLV0z' #luciano


API_KEY = ''


REDIRECT_URI = 'http://localhost:5003/callback'

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
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    print "resuts"
    print results
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
    url = "http://localhost:5000/api/whois"
    params = {'access_token': access_token}
    print "toke es"
    print access_token

#############################################
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
#############################################
    nombre = "juan"
    nombre = results['username']
    return nombre

#####################################  HERE FUNCTIONS ###########################################

def query_products(page, PER_PAGE,access_token):
    url = "http://localhost:5000/api/productos"
    params = {'access_token': access_token, 'page': page, 'per_page' : PER_PAGE}
    print "toke es"
    print access_token

#############################################
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
#############################################
    print "results"
    print results

    return results

PER_PAGE = 10

@app.route('/productos', defaults={'page': 1})
@app.route('/productos/<int:page>')
def show_products(page):
    token=login_session.get('access_token')
    productos = query_products(page, PER_PAGE,token)
    print productos
    if not productos and page != 1:
        print "nothing"
        #abort(404)

    count=200
    pagination = Pagination(page, PER_PAGE, count)
    return render_template('productsu.html', pagination=pagination, products=productos )


#####################################  HERE FUNCTIONS ###########################################
### HOMEPAGE  ###
@app.route('/')
def index():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return flask.render_template('store.html', url=auth_url())


@app.route('/me')
def askaboutme():
    print "token actual"
    unnombre="j"
    exp="hoy"
    if login_session.get('access_token') is None:
        return redirect(url_for("index"))
    tk = login_session['access_token']
    unnombre=get_profile(tk)

    exp=login_session['expira']
    print unnombre
    return flask.render_template('usersu.html', USERNAME=unnombre, EXPIRE=exp)


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
    user = args.get('user', None)
    if not code:
        return "Authentication error: no code provided"
    print "args"
    print args
    print "code"
    print code
    tokens = code_for_token(code)
    acc_token = tokens[0]
    login_session['access_token'] = acc_token
    ref_token = tokens[1]
    expira = tokens[3]
    ahora=datetime.now()
    print "ahora"
    print ahora
    print "expira"
    print expira
    print expira[1]
    expiral = datetime(int(expira[0]),int(expira[1]),int(expira[2]),int(expira[3]),int(expira[4]),int(expira[5]))
    print "espiral"
    print expiral
    user=get_profile(acc_token)
    login_session['expira'] = expiral
    if expiral > ahora:
        estado = "vigente"
    else:
        estado = "vencido"
    return render_template("indexu.html", NOW=ahora,WHO=user, STATUS=estado, EXPIRES=expiral)

if __name__ == '__main__':
    app.secret_key = 'twtrtretrefsdgfgvbcvbbvbcviutiujgkhj'
    app.run(host='127.0.0.1', port=5003, use_reloader=False)