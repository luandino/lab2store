#!/usr/bin/env python
import os
import flask
from flask import Flask, abort, session, request, jsonify, g, url_for, render_template, redirect
#from flask.ext.sqlalchemy import SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
#from sqlalchemy.sql import column, func

from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from flask import send_from_directory
from werkzeug.security import gen_salt
#from graphviz import Digraph
from datetime import datetime, timedelta
import urllib
import json


# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'rewrewtrtrewsadsdwredsadrqeqw'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
### NEEDED TO USE BOOTSTRAP'S TEMPLATES  ###
from flask_bootstrap import Bootstrap


# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

def create_app():
  app = Flask(__name__)
  Bootstrap(app)
  return app

#dot = Digraph(comment='The Big Network')

#dot.node('A', 'Anna')
#dot.node('E', 'Elena')
#dot.node('L', 'Luciano')
#dot.edges(['AL', 'EL'])


#dot.render('/home/luciano/izmailovo/lab2store/tmp/round-table.gv', view=True)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(40), unique=True)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

 #   @staticmethod
  #  def get_count(self):
   #     var = self.session.query(func.count('*')).select_from(self.model)
    #    return var



class Client(db.Model):
    #__tablename__ = 'cliente'
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []

class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    user = db.relationship('User') # UNA RELACION CON LA CLASE USUARIO

    client_id = db.Column(db.String(40), db.ForeignKey('client.client_id'), nullable=False, )
    client = db.relationship('Client')   # UNA RELACION CON LA CLASE CLIENTE

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('users.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

########################################################################
# @app.route('/api/users', methods=['POST'])
# def new_user():
#     username = request.json.get('username')
#     password = request.json.get('password')
#     #confirm = request.json.get('confirm-password')
#     if username is None or password is None or password:
#         abort(400)    # missing arguments
#     if User.query.filter_by(username=username).first() is not None:
#         abort(400)    # existing user
#     user = User(username=username)
#     user.hash_password(password)
#     db.session.add(user)
#     db.session.commit()
#     session['id'] = user.id
#     return (jsonify({'username': user.username}), 201,
#             {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/api/register', methods=('GET','POST'))
def users():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username is None or password is None:
            abort(400)    # missing arguments
        if User.query.filter_by(username=username).first() is not None:
            username="existente"
            password="sinsentido"
        else:
            user = User(username=username)
            user.hash_password(password)
            db.session.add(user)
            db.session.commit()
            session['id'] = user.id
            print "user id"
            print user.id
            item = Client(client_id=gen_salt(40),
                          client_secret=gen_salt(50),
                          user_id=user.id,
                          _redirect_uris='http://localhost:5001/callback',
                          _default_scopes='email')
            db.session.add(item)
            db.session.commit()
        return flask.render_template('users.html', NEWUSER=username, PASS=password, CI=item.client_id, CS=item.client_secret)



#@app.route('/client')
def client():
     user = current_user()
     #if not user:
     #    return redirect('/')
     item = Client(
         client_id=gen_salt(40),
         client_secret=gen_salt(50),
         _redirect_uris='http://localhost:8000/authorized',
         _default_scopes='email',
         user_id=user.id,
     )
     db.session.add(item)
     db.session.commit()
     return jsonify(client_id=item.client_id,client_secret=item.client_secret)




#@oauth.grantsetter
def save_grant(user_id,client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.now() + timedelta(seconds=300)
    grant = Grant(
        user_id=user_id,
        client_id=client_id,
        code=code,
        redirect_uri=request,
        _scopes='mail',
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


####################################################################################

@app.route('/api/enter', methods=('GET','POST'))
def enter():
    #username = request.json.get('username')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
    #confirm = request.form.get('confirm-password')
        if username is None or password is None:
            abort(400)    # missing arguments
        if User.query.filter_by(username=username).first() is not None:
            #username="existente"
            #password="noimporta"
            abort(400)    # existing user
    #user = User(username=username)
    #user.hash_password(password)
    #db.session.add(user)
    #db.session.commit()
    return flask.render_template('users.html', NEWUSER=username, PASS=password)


@app.route('/api/login', methods=('GET', 'POST'))
def login():
    if request.method == 'GET':
        return flask.render_template('/client/login_with_registration.html')


############################################

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})



def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


@app.route('/api/token', methods=['POST'])
def recibirtoken():
    datos=request.get_json() # OPCION 1
    #datos = request.args() # OPCION 2
    #unakey='blabla' # OPCION 3
    #datos = request.args # OPCION 4

    unakey = datos['code']
    print "Recibido"
    print unakey
    encontrado=Grant.query.filter_by(code=unakey).first()

    if encontrado is not None:
        print "se encontro el Grant para ese code"
        print "Grant user_id"
        print encontrado.user_id
        print "Grant client_id"
        print encontrado.client_id
        present = datetime.now()
        print "encontrado expira en"
        print encontrado.expires
        print "fecha presente"
        print present
        if encontrado.expires > present:
            print "el gran era valido"
            unClient=Client.query.filter_by(client_id=encontrado.client_id).first()
            unUser=User.query.filter_by(id=encontrado.user_id).first()
            secondos=600
            acct=gen_salt(40)
            accr=gen_salt(40)
            cuando=datetime.now() + timedelta(seconds=secondos)
            if unClient is not None and unUser is not None:
                print "entra para crear el token"
                unToken=Token(user_id=unUser.id,
                              client_id=unClient.client_id,
                              token_type="bearer",
                              access_token=acct,
                              refresh_token=accr,
                              expires=cuando,
                              _scopes="all")
                db.session.add(unToken)
                db.session.commit()
                print "cuando"
                print cuando
                return jsonify(
                    {"access_token": acct, "token_type": "bearer", "refresh_token": acct, "expires_in": secondos, "expires": cuando})

            else:
                print "no tuvo los datos para crear el token"
                return jsonify({"access_token": "datos_erroneos",
                                "token_type": "bearer",
                                "refresh_token":
                                "y bueno",
                                "expires_in": 0})

        else:
            print "el grant tiene la fecha vieja"
            print encontrado.expires
            return jsonify({"access_token": "era_un_code_viejo","token_type": "bearer", "refresh_token": "jajajajaj", "expires_in": 0})

    else:
        print "encontrando is none"
    return jsonify({"access_token": "hola", "token_type": "bearer", "refresh_token": "chau", "expires_in": 0})

# @app.route('/api/token', methods=['POST'])
# def recibirtoken():
#     #datos=request.args
#     datos=request.get_json()
#     #elcode = recibido['code']
#     #elcode='oQGwGOpzGmqkON9K4V7adCbGnQcbvQytjiDOGUDy'
#     elcode=datos['code']
#     print "en recibirtoken, se recibio esto"
#     print elcode #datos['key1']
#     #return jsonify({"access_token": "era_un_code_viejo",
#     #                "token_type": "bearer",
#     #                "refresh_token": "jajajajaj",
#     #                "expires_in": 0})
#     #elcode='oQGwGOpzGmqkON9K4V7adCbGnQcbvQytjiDOGUDy'
#     #grantype = request.args.get('grant_type')
#     #toks = Token.query.filter_by(
#     #    client_id=request.client.client_id,
#     #    user_id=request.user.id
#     #)
#     encontrado=Grant.query.filter_by(code=elcode).first()
#     print "se encontro el Grant para ese cdigo"
#     print encontrado.user_id
#     print encontrado.client_id
#
#     if encontrado is not None:
#         present = datetime.now()
#         if encontrado.expires > present:
#             unClient=Client.query.filter_by(client_id=encontrado.client_id)
#             unUser=User.query.filter_by(id=encontrado.user_id)
#             secondos=600
#             acct=gen_salt(40)
#             accr=gen_salt(40)
#
#             unToken=Token(user_id=unUser.id,
#                           client_id=unClient.id,
#                           token_type="bearer",
#                           access_token=acct,
#                           refresh_token=accr,
#                           expires=datetime.now() + timedelta(seconds=secondos),
#                           _scopes="all"
#                           )
#             db.session.add(unToken)
#             db.session.commit()
#             return jsonify({"access_token": acct,
#                             "token_type": "bearer",
#                             "refresh_token": accr,
#                             "expires_in": secondos})
#         else:
#             print "el gran tiene la fecha"
#             print encontrado.expires
#             return jsonify({"access_token": "era_un_code_viejo",
#                             "token_type": "bearer",
#                             "refresh_token": "jajajajaj",
#                             "expires_in": 0})
#     return jsonify({"access_token": "holaquetal", "token_type": "bearer" , "refresh_token": "chauuu", "expires_in": 0})


@app.route('/api/resource')
@auth.login_required

#      return jsonify({"error": "unauthorized","error_description": "Full authentication is required to access this resource"})

def get_resource():
    #return jsonify({'data': 'Hello John'})
    return jsonify({'data': 'Hello, %s!' % g.user.username})

@app.route('/api/me')
@auth.login_required
def myname():
    return jsonify({'user': '%s' % g.user.username})

#return jsonify({"error": "unauthorized","error_description": "Full authentication is required to access this resource"})

################### PUBLIC METHOD ########################
@app.route('/ping',  methods=['GET'])
def public_method():
    return "OK"
    #return jsonify({'public': 'OK'})


@app.route('/api/authorize', methods=['GET', 'POST'])
#@oauth.authorize_handler
def authorize(*args, **kwargs):
    #user = current_user()
    #if not user:
    #    return redirect('/')
    if request.method == 'GET':
        client_id = request.args.get('client_id') #kwargs.get('client_id')
        #print "cl id"
        #print client_id
        session['client_id'] = client_id
        cliente_encontrado = Client.query.filter_by(client_id=client_id).first()
        #kwargs['client'] = client_id
        #print "cliente encontrado"
       # print cliente_encontrado
       # print "cliente encontrado_id"
        #valorid=cliente_encontrado.client_id
        #print valorid
        #print "cliente encontrado_user_id"
        #print cliente_encontrado.user_id
        session['user_id']=cliente_encontrado.user_id
        usuario_encontrado = User.query.filter_by(id=cliente_encontrado.user_id).first()
        #print "usuario encontrado"
        #print usuario_encontrado.username
        nombre=usuario_encontrado.username
        #kwargs['user'] = "luciano" #usuario_encontrado.username
        return render_template('authorize.html', NOMBRE=nombre)
    if request.method == 'POST':
        passplano = request.form.get('password')
        #jash=pwd_context.encrypt(passplano)

        usuario_encontrado = User.query.filter_by(id=1).first()
        #print "hash de introducido"
        #print pwd_context.encrypt(passplano)
        #print "usuario"
        #print usuario_encontrado.username
        #print usuario_encontrado.verify_password(passplano)
        #if usuario_encontrado.password_hash != pwd_context.encrypt(passplano) is None:
        if not usuario_encontrado.verify_password(passplano):
            #print "flaso"
            return redirect("http://www.google.com/")
        else:
            code=gen_salt(40)
            #nuevogrant=save_grant(session['client_id'], code, request)
            #print "bien"
            url = "http://localhost:5001/callback"
            params = {'code': code}
            # crear el grant asociado al usuario y al cliente
            #poniendole el token
            # borrando grants asociados anteriores
            # guardando el grant
            #enviar el code del grant devuelta para que del otro lado nos manden
            # la peticion de que quieren un token con el code como paramentro
            un_grant=save_grant(session['user_id'],session['client_id'], code, url)
            #print "ungrant id"
            #print un_grant.id
            #print "un code generado recien"
            #print code
            return redirect("{0}?{1}".format(url, urllib.urlencode(params)))
            #return True
        # jash=hash_password(passplano)
        #usuario_encontrado2 = User.query.filter_by(id=cliente_encontrado.user_id).first()
    #confirm = request.form.get('confirm', 'no')
    #return confirm == 'yes'


#def authorize():
    #user = current_user()
    #if not user:
    #    return redirect('/')
    # if request.method == 'GET':
    #     client_id = kwargs.get('client_id')
    #     client = Client.query.filter_by(client_id=client_id).first()
    #     print "se recibio este client_id"
    #     print client_id
    #     kwargs['client'] = client
    #     kwargs['user'] = 'edor'
    #print "elid"
    #clientid=request.args.get('client_id')
    #print clientid
    #return jsonify({'username': 'hise' })
    #    return render_template('authorize.html', **kwargs)

    #confirm = request.form.get('confirm', 'no')
    #return confirm == 'yes'

@app.route('/api/flush')
def flushvars():
    Grant.query.delete()
    Token.query.delete()
    return redirect('/api/printvars')


@app.route('/api/printvars')
def printvariables():
    tokensi = []
    grants = []
    cantidad=Grant.query.count()
    ahora = datetime.now()
    if cantidad >0 :
        resultado = Grant.query.filter_by()
        entries = resultado.all()



        for entry in entries:
            if entry.expires > ahora:
                estado="valido"
            else:
                estado="vencido"
            grants.append({'user_id': entry.user_id,
                          'client_id': entry.client_id,
                          'code': entry.code,
                          'expire': entry.expires,
                          'estado': estado})
            # print "info de un Grant"
            # print entry.user_id
            # print entry.client_id
            # print entry.code
            # print entry.expires

    canttoken = Token.query.count()
    if canttoken > 0:
        resultadotoken = Token.query.filter_by()
        entrytoken = resultadotoken.all()


        for entry in entrytoken:
            if entry.expires > ahora:
                estado="valido"
            else:
                estado="vencido"

            tokensi.append({'id': entry.id,
                            'user_id': entry.user_id,
                            'client': entry.client_id,
                            'token_type': entry.token_type,
                            'access_token': entry.access_token,
                            'refresh_token': entry.refresh_token,
                            'expires': entry.expires,
                            '_scopes': entry._scopes,
                            'estado' : estado
                            })
            # print "info de un Grant"
            # print entry.id
            # print entry.client_id
            # print entry.user_id
            # print entry.access_token
            # print entry.refresh_token
            # print entry.expires
            # print entry._scopes
    return flask.render_template('printvars.html', items=grants, toquens=tokensi)


@app.route('/')
def index():
    session.clear
    #state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    #login_session['state'] = state
    reg = User.query.count()
    on = 1
    cli = Client.query.count()
    return flask.render_template('index.html',REGISTERED=reg,ONLINE=on,CLIENTS=cli)

if __name__ == '__main__':
    #if not os.path.exists('db.sqlite'):
    db.create_all()
    app.run(debug=True)
