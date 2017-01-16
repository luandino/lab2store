#!/usr/bin/env python
import os
import flask
from flask import Flask, abort, session, request, g, url_for, render_template, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from flask import send_from_directory
from werkzeug.security import gen_salt
from datetime import timedelta
from datetime import datetime
import urllib
import numpy as np
from numpy import genfromtxt
from time import time

from sqlalchemy.ext.declarative import declarative_base
from flask_bootstrap import Bootstrap
from flask import abort
PER_PAGE = 10





# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'rewrewtrtrewsadsdwredsadrqeqw'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True




# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

def create_app():
  app = Flask(__name__)
  Bootstrap(app)
  return app

######################################## DATABASE DEFINITION AND FUNCTIONS ########################################

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')



class Product(db.Model):
    product_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(62))
    description = db.Column(db.String(80))
    price = db.Column(db.Integer)

class Stock(db.Model):
    stock_id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer)
    product_id = db.Column(db.String(40), db.ForeignKey('product.product_id'), nullable=False)
    product = db.relationship('Product')

class Order(db.Model):
    order_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OrderItem(db.Model):
    orderitem_id = db.Column(db.Integer, primary_key=True)

    order_id = db.Column(db.Integer, db.ForeignKey('order.order_id', ondelete='CASCADE'))
    user = db.relationship('Order')

    product_id = db.Column(db.Integer, db.ForeignKey('product.product_id'))
    product = db.relationship('Product')


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    password_hash = db.Column(db.String(64))
    created = db.Column(db.DateTime)

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


############################  END DATABASE DEFINITION AND FUNCTIONS #################################

################### RUNS ONLY LOCALLY, HERE USER REGISTER ###########################################
################### AND RECEIVE A CLIENT_ID AND CLIENT SECRET #######################################

@app.route('/api/register', methods=('GET','POST'))
def users():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        clienturl = request.form.get('url')
        if len(username)==0 and len(password)==0:
            return flask.render_template('users.html', USERNAME=username, NEWUSER=" Username ", PASS=" and password ",
                                         CI=" are empty ", CS=" go to register page again ")
        if User.query.filter_by(username=username).first() is not None:
            username=" Please go to register page "
            password=" again, the username "
            return flask.render_template('users.html', USERNAME=username, NEWUSER=username, PASS=password,
                                         CI=" you choosed ", CS=" is already taken ")

        else:
            user = User(username=username,created=datetime.now())
            user.hash_password(password)
            db.session.add(user)
            db.session.commit()
            session['id'] = user.id
            print "user id"
            print user.id
            item = Client(client_id=gen_salt(40),
                          client_secret=gen_salt(50),
                          user_id=user.id,
                          _redirect_uris=clienturl,
                          _default_scopes='email')
            db.session.add(item)
            db.session.commit()
        return flask.render_template('users.html', USERNAME=username, NEWUSER=username, PASS=password, CI=item.client_id, CS=item.client_secret)

############################# END REGISTER PART ##########################################

#@app.route('/client')
def client():
     user = current_user()
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


############################ ??? NO ESTAN SIENDO UTILIZADAS  #########################################

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


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

############################# ??? FIN NO ESTAN SIENDO UTILIZADAS  ####################################


############################  LLAMADAS A OPERACIONES EN EL SERVIDOR  ##################################


############################ RECEIVE GRANT AND IF IT IS IN DATABASE     ###############################
############################  I RETURN A TOKEN_ACCESS AND REFRESH TOKEN ###############################


@app.route('/api/token', methods=['GET', 'POST'])
def sendtoken():
    datos=request.get_json()
    unakey = datos['code']
    print "Recibido"
    print unakey
    encontrado=Grant.query.filter_by(code=unakey).first()

    if encontrado is not None:
        present = datetime.now()
        if encontrado.expires > present:
            print "el gran era valido"
            unClient=Client.query.filter_by(client_id=encontrado.client_id).first()
            unUser=User.query.filter_by(id=encontrado.user_id).first()
            secondos=600
            acct=gen_salt(40)
            accr=gen_salt(40)
            cuando=datetime.now() + timedelta(seconds=secondos)
            print "cuando"
            vect=[]
            vect.append(cuando.strftime("%Y"))
            vect.append(cuando.strftime("%m"))
            vect.append(cuando.strftime("%d"))
            vect.append(cuando.strftime("%H"))
            vect.append(cuando.strftime("%M"))
            vect.append(cuando.strftime("%S"))
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

                return jsonify({"access_token": acct,
                                "token_type": "bearer",
                                "refresh_token": acct,
                                "expires_in": secondos,
                                "expires": vect})

            else:
                print "no tuvo los datos para crear el token"
                return jsonify({"access_token": "datos_erroneos",
                                "token_type": "bearer",
                                "refresh_token":
                                "y bueno",
                                "expires_in": 0})

        else:
            print "el grant tiene la fecha vieja"
            print "delete old grant"
            print encontrado.expires
            db.session.add(encontrado)
            db.session.commit()
            return jsonify({"access_token": "era_un_code_viejo","token_type": "bearer", "refresh_token": "jajajajaj", "expires_in": 0})

    else:
        print "encontrando is none"
    return jsonify({"access_token": "invalid", "token_type": "bearer", "refresh_token": "invalid", "expires_in": 0})

################### PUBLIC METHOD ########################
@app.route('/ping',  methods=['GET'])
def public_method():
    return "OK"
    return jsonify({'public': 'OK'})

################### PRIVATE METHODS ###################################################################################
@app.route('/api/whois', methods=['POST'])
#@oauth.authorize_handler
def whois():
    nombre="expired"
    if request.method == 'POST':
        datos = request.get_json()
        print "se recibio esto"
        un_token = datos['access_token']
        print un_token
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        if token_encontrado is not None:
            print "token encontrado"
            usuario_encontrado = User.query.filter_by(id=token_encontrado.user_id).first()
            print "usuario encontrado"
            print usuario_encontrado.username
            nombre=usuario_encontrado.username
    return jsonify({'username': nombre})


#######################################################################################################################
@app.route('/api/authorize', methods=['GET', 'POST'])
def authorize(*args, **kwargs):

    if request.method == 'GET':
        print "el recquest metod es "
        print request.method
        client_id = request.args.get('client_id')
        session['client_id'] = client_id
        cliente_encontrado = Client.query.filter_by(client_id=client_id).first()
        print "llego este cliente id"
        print client_id
        session['user_id']=cliente_encontrado.user_id
        session['url']=cliente_encontrado._redirect_uris
        usuario_encontrado = User.query.filter_by(id=cliente_encontrado.user_id).first()

        nombre=usuario_encontrado.username

        return render_template('authorize.html', NOMBRE=nombre)
    if request.method == 'POST':
        print "el request metod 2 es "
        print request.method
        passplano = request.form.get('password')
        nameuser = request.form.get('nombre')

        usuario_encontrado = User.query.filter_by(username=nameuser).first()
        cliente_encontrado = Client.query.filter_by(user_id=usuario_encontrado.id).first()
        url_callback=cliente_encontrado._redirect_uris
        print "se logueo con este usuario"
        print usuario_encontrado.username
        if not usuario_encontrado.verify_password(passplano):
            session.clear()
            return redirect("http://www.google.com")
        else:
            code=gen_salt(40)
            url = url_callback
            params = {'code': code}
            print "user id"
            print session['user_id']
            print "client id"
            print session['client_id']
            save_grant(session['user_id'],session['client_id'], code, url)
            return redirect("{0}?{1}".format(url, urllib.urlencode(params)))




@app.route('/api/flush')
def flushvars():
    Grant.query.delete()
    Token.query.delete()
    #User.query.delete()
    #Client.query.delete()
    #Product.query.delete()
    return redirect('/api/printvars')


@app.route('/api/printvars')
def printvariables():
    tokensi = []
    grants = []
    usuarios = []
    clientes = []
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
    cantusers = User.query.count()
    if cantusers > 0:
        resultadousers = User.query.filter_by()
        entryusers = resultadousers.all()

        for entry in entryusers:
            usuarios.append({'id': entry.id,
                            'username': entry.username,
                            'created': entry.created.strftime("%Y-%m-%d %H:%M:%S")
                            })

    cantclie = Client.query.count()
    if cantclie > 0:
        resultadoclients = Client.query.filter_by()
        entryclie = resultadoclients.all()

        for entry in entryclie:
            clientes.append({'client_id': entry.client_id,
                             'client_secret': entry.client_secret,
                             'user_id': entry.user_id,
                             'client_url': entry._redirect_uris
                            })


    return flask.render_template('printvars.html', items=grants, toquens=tokensi, users=usuarios, clients=clientes)



def Load_Data(file_name):
    data = genfromtxt(file_name, delimiter=',', skiprows=1, converters={0: lambda s: str(s)})
    return data.tolist()

Base = declarative_base()


@app.route('/api/loaddata')
def loaddata():
    registros=1
    t = time()
    try:
        data = np.genfromtxt("/home/luciano/izmailovo/lab2store/super.csv", dtype=None, usemask=True, delimiter=",")
        for i in data:
            print "registro "
            print registros
            record = Product(**{
                'name' : i[0],
                'description' : i[1],
                'price' : i[2]
            })
            registros=registros+1
            db.session.add(record)
            db.session.commit()


        #s.commit() #Attempt to commit all the records
    except:
        print "algo fallo"
        db.session.rollback() #Rollback the changes on error
    #finally:
    #    db.session.on.close() #Close the connection
    print "Time elapsed: " + str(time() - t) + " s." #0.091s
    return redirect('/')
############################################################3
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

#######
def get_products_for_page(page, PER_PAGE):
    productos = []

    if page == 1:
       desde = 0
    else:
        desde=(page-1)*PER_PAGE
    print "desde"
    print desde
    hasta=desde+PER_PAGE
    print hasta
    resultado = Product.query.filter_by()
    entries = resultado.slice(desde,hasta).all()



    for entry in entries:
        print entry.product_id
        print entry.name

        productos.append({'name': entry.name,
                          'description': entry.description,
                          'price': entry.price})
    return productos



##################################### REMOTA ##############################################33
@app.route('/api/productos', defaults={'page': 1} , methods=('GET','POST'))
@app.route('/api/productos/<int:page>', methods=('GET','POST'))
#@login_required
def show_productos(page):
    print "method"
    print request.method
    if request.method == 'POST':
        datos = request.get_json()
        print "se recibio esto"
        un_token = datos['access_token']
        user_per_page = datos['per_page']
        user_page = datos['page']
        print un_token
        print "numero de hoja"
        print user_page
        print "por pagina"
        print user_per_page
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        if token_encontrado is not None:
            print "token encontrado"
            productos = get_products_for_page(user_page, user_per_page)
            print productos
            return jsonify(productos)
        else:
            return jsonify({'name': '', 'description': '', 'price': ''})
    else:
        return jsonify({'name': '', 'description': '','price': ''})



##################################### LOCAL ##############################################33
@app.route('/api/products', defaults={'page': 1})
@app.route('/api/products/<int:page>')
def show_products(page):
    count = Product.query.count()
    print "cuantos productos"
    print count

    productos = get_products_for_page(page, PER_PAGE)
    print productos
    if not productos and page != 1:
        abort(404)
    pagination = Pagination(page, PER_PAGE, count)
    return render_template('products.html', pagination=pagination, products=productos )


##############################################################################3

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
