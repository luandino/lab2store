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
from math import ceil

from sqlalchemy.ext.declarative import declarative_base
from flask_bootstrap import Bootstrap
from flask import abort
PER_PAGE = 10



app = Flask(__name__)
app.config['SECRET_KEY'] = 'rewrewtrtrewsadsdwredsadrqeqw'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


db = SQLAlchemy(app)
auth = HTTPBasicAuth()

def create_app():
  app = Flask(__name__)
  Bootstrap(app)
  return app

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')

########################################## DATABASE DEFINITION AND FUNCTIONS ##########################################

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
    date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    user = db.relationship('User')
    status = db.Column(db.String(80))


class OrderItem(db.Model):
    orderitem_id = db.Column(db.Integer, primary_key=True)

    order_id = db.Column(db.Integer, db.ForeignKey('order.order_id', ondelete='CASCADE'))
    order = db.relationship('Order')

    product_id = db.Column(db.Integer, db.ForeignKey('product.product_id'))
    product = db.relationship('Product')
    quantity = db.Column(db.Integer)

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
    #
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





####################### REGISTER: USER, PASSWORD AND CALLBACK ADDRESS IN CLIENT #######################################

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
            item = Client(client_id=gen_salt(40),
                          client_secret=gen_salt(50),
                          user_id=user.id,
                          _redirect_uris=clienturl,
                          _default_scopes='email')
            db.session.add(item)
            db.session.commit()
        return flask.render_template('users.html', USERNAME=username, NEWUSER=username, PASS=password, CI=item.client_id,
                                     CS=item.client_secret)






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


####################### CREATE TOKE AFTER RECEIVING VALID GRANT #######################################

@app.route('/api/token', methods=['GET', 'POST'])
def sendtoken():
    datos=request.get_json()
    unakey = datos['code']
    encontrado=Grant.query.filter_by(code=unakey).first()

    if encontrado is not None:
        present = datetime.now()
        if encontrado.expires > present:
            unClient=Client.query.filter_by(client_id=encontrado.client_id).first()
            unUser=User.query.filter_by(id=encontrado.user_id).first()
            secondos=7200
            acct=gen_salt(40)
            accr=gen_salt(40)
            cuando=datetime.now() + timedelta(seconds=secondos)
            vect=[]
            vect.append(cuando.strftime("%Y"))
            vect.append(cuando.strftime("%m"))
            vect.append(cuando.strftime("%d"))
            vect.append(cuando.strftime("%H"))
            vect.append(cuando.strftime("%M"))
            vect.append(cuando.strftime("%S"))
            if unClient is not None and unUser is not None:
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
                return jsonify({"access_token": "datos_erroneos",
                                "token_type": "bearer",
                                "refresh_token":
                                "y bueno",
                                "expires_in": 0})

        else:
            #db.session.add(encontrado)
            #db.session.commit()
            return jsonify({"access_token": "era_un_code_viejo","token_type": "bearer", "refresh_token": "jajajajaj", "expires_in": 0})

    return jsonify({"access_token": "invalid", "token_type": "bearer", "refresh_token": "invalid", "expires_in": 0})

########################################### PUBLIC METHOD: ANSWER TO PING ##############################################
@app.route('/api/ping',  methods=('GET','POST'))
def public_method():
    hora=datetime.now()
    return jsonify({'answer': 'OK', 'time' : hora})

#################################################### PRIVATE METHODS ###################################################
@app.route('/api/whois', methods=('GET','POST'))
#@oauth.authorize_handler
def whois():
    nombre="Guest"
    if request.method == 'POST':
        datos = request.get_json()
        un_token = datos['access_token']
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        ahora=datetime.now()
        if token_encontrado is not None and token_encontrado.expires > ahora:
            usuario_encontrado = User.query.filter_by(id=token_encontrado.user_id).first()
            nombre=usuario_encontrado.username

    elif request.method == 'GET':
        print "df"

    return jsonify({'username': nombre})



###############################################    AUTHORIZE AT LOGIN    #############################################
@app.route('/api/authorize', methods=['GET', 'POST'])
# @oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = request.args.get('client_id')
        session['client_id'] = client_id
        cliente_encontrado = Client.query.filter_by(client_id=client_id).first()
        session['user_id']=cliente_encontrado.user_id
        session['url']=cliente_encontrado._redirect_uris
        usuario_encontrado = User.query.filter_by(id=cliente_encontrado.user_id).first()
        nombre=usuario_encontrado.username
        return render_template('authorize.html', NOMBRE=nombre)
    if request.method == 'POST':
        passplano = request.form.get('password')
        nameuser = request.form.get('nombre')

        usuario_encontrado = User.query.filter_by(username=nameuser).first()
        cliente_encontrado = Client.query.filter_by(user_id=usuario_encontrado.id).first()
        url_callback=cliente_encontrado._redirect_uris
        if not usuario_encontrado.verify_password(passplano):
            session.clear()
            return redirect("http://www.google.com")
        else:
            code=gen_salt(40)
            url = url_callback
            params = {'code': code}
            save_grant(session['user_id'],session['client_id'], code, url)
            return redirect("{0}?{1}".format(url, urllib.urlencode(params)))



###############################################  UTILITY: FLUSH VARS    #############################################

@app.route('/api/flush')
def flushvars():
    Grant.query.delete()
    Token.query.delete()
    Order.query.delete()
    OrderItem.query.delete()
    #User.query.delete()
    #Client.query.delete()
    #Product.query.delete()
    return redirect('/api/printvars')

###############################################  UTILITY: PRINT VARS    #############################################
@app.route('/api/printvars')
def printvariables():
    tokensi = []
    grants = []
    usuarios = []
    clientes = []
    ordenes = []
    itemsordenes = []
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
                estado="Valid"
            else:
                estado="Deprecated"

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
    cantOrders = Order.query.count()
    if cantOrders > 0:
        resultadoordenes = Order.query.filter_by()
        entryordenes = resultadoordenes.all()

        for entry in entryordenes:
            ordenes.append({'order_id': entry.order_id,
                             'date': entry.date,
                             'user_id': entry.user_id,
                             'status': entry.status
                            })
    cantitemordenes = OrderItem.query.count()
    if cantitemordenes > 0:
        resultadoitemsordenes = OrderItem.query.filter_by()
        entryitemsordenes = resultadoitemsordenes.all()

        for entry in entryitemsordenes:
            itemsordenes.append({'orderitem_id': entry.orderitem_id,
                             'order_id': entry.order_id,
                             'product_id': entry.product_id,
                             'quantity': entry.quantity
                            })

    return flask.render_template('printvars.html', items=grants, toquens=tokensi, users=usuarios, clients=clientes, orders=ordenes, ios=itemsordenes)



def Load_Data(file_name):
    data = genfromtxt(file_name, delimiter=',', skiprows=1, converters={0: lambda s: str(s)})
    return data.tolist()

Base = declarative_base()

########################################  UTILITY: UPLOAD CSV TO PRODUCT TABLE    ######################################

@app.route('/api/loaddata')
def loaddata():
    registros=1
    t = time()
    try:
        data = np.genfromtxt("/home/luciano/izmailovo/csv/super.csv", dtype=None, usemask=True, delimiter=",")
        for i in data:
            record = Product(**{
                'name' : i[0],
                'description' : i[1],
                'price' : i[2]
            })
            registros=registros+1
            db.session.add(record)
            db.session.commit()
    except:
        db.session.rollback()

    print "Time elapsed: " + str(time() - t) + " s."


########################################### CLIENT SIDE PAGINATION    #############################################
def get_products_for_page(page, PER_PAGE):
    productos = []

    if page == 1:
       desde = 0
    else:
        desde=(page-1)*PER_PAGE
    hasta=desde+PER_PAGE
    resultado = Product.query.filter_by()
    entries = resultado.slice(desde,hasta).all()
    for entry in entries:
        productos.append({'product_id': entry.product_id,
                          'name': entry.name,
                          'description': entry.description,
                          'price': entry.price})
    return productos


def get_orders_for_page(page, PER_PAGE,token):
    orders = []

    if page == 1:
       desde = 0
    else:
        desde=(page-1)*PER_PAGE
    hasta=desde+PER_PAGE
    resultado = Order.query.filter_by(user_id=token.user_id)
    entries = resultado.slice(desde,hasta).all()
    for entry in entries:
        orders.append({'order_id': entry.order_id,
                       'user_id': token.user_id,
                       'date': entry.date,
                       'status': entry.status})
    return orders



###############################################  CREATE A NEW ORDER    ###############################################

@app.route('/api/order', methods=['POST'])
def order():
    number="expired"
    if request.method == 'POST':
        datos = request.get_json()
        un_token = datos['access_token']
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        ahora=datetime.now()
        if token_encontrado is not None and token_encontrado.expires > ahora:
            usuario_encontrado = User.query.filter_by(id=token_encontrado.user_id).first()
            ahora = datetime.now()
            unaOrder = Order(user_id=usuario_encontrado.id, status="Unpaid", date=ahora)
            db.session.add(unaOrder)
            db.session.commit()
            return jsonify({'order': unaOrder.order_id, 'date' : unaOrder.date})
    return jsonify({'order': "null", 'date': "null"})

##############################################  PAY AN ORDER    #######################################################

#@app.route('/api/order', defaults={'order_n': 1, 'prod_n': 1}, methods=('GET', 'POST', 'DELETE'))
@app.route('/api/order/<int:order_id>/billing', methods=('GET','POST'))
def billing(order_id):
    resumen = {'order_id': 0, 'user_id': 0, 'status': '', 'date': ''}
    respuesta=[]
    sum = {'suma': 0}
    respuesta.append({'orderitem_id': '', 'order_id': '', 'product_id': '', 'quantity': 0})
    if request.method == 'POST':
        datos = request.get_json()
        un_token = datos['access_token']
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        ahora=datetime.now()
        if token_encontrado is not None and token_encontrado.expires > ahora:
            usuario_encontrado = User.query.filter_by(id=token_encontrado.user_id).first()
            order_encontrado = Order.query.filter_by(order_id=order_id).first()
            if order_encontrado.user_id==usuario_encontrado.id and order_encontrado.status == "Unpaid":
                order_encontrado.status="Paid"
                resumen = {'order_id': order_encontrado.order_id, 'user_id': order_encontrado.user_id,'status': order_encontrado.status, 'date': order_encontrado.date}
                suma=0
                respuesta=order_items_in_order(order_id)
                if request is not None:
                    for item in respuesta:
                        producto_encontrado = Product.query.filter_by(product_id=item['product_id']).first()
                        if producto_encontrado is not None:
                            suma_parcial=producto_encontrado.price*item['quantity']
                            suma=suma+suma_parcial
                sum = {'suma':suma}
                return jsonify({'sum': sum, 'resume' : resumen, 'detail' : respuesta})
        return jsonify({'sum': sum, 'resume': resumen, 'detail': respuesta})
    return jsonify({'sum': sum, 'resume': resumen, 'detail': respuesta})

###########################################  ORDER'S PAGINATION    ###############################################

@app.route('/api/orders', defaults={'page': 1}, methods=('GET', 'POST'))
@app.route('/api/orders/<int:page>', methods=('GET', 'POST'))
def show_orders(page):
    if request.method == 'POST':
        datos = request.get_json()
        un_token = datos['access_token']
        user_per_page = datos['per_page']
        user_page = datos['page']
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        ahora = datetime.now()
        if token_encontrado is not None and token_encontrado.expires > ahora:
            orders = get_orders_for_page(user_page, user_per_page,token_encontrado)
            return jsonify(orders)
        else:
            return jsonify({'order_id' : 0, 'user_id':'old', 'date': 'old', 'status': 'old'})
    else:
        return jsonify({'order_id': 0, 'user_id':'unknown', 'date': 'unknown', 'status': 'unknown'})


###############################################  ORDER'S DETAIL    ###############################################


@app.route('/api/orderdetail', defaults={'order_id': 1}, methods=('GET', 'POST'))
@app.route('/api/orderdetail/<int:order_id>', methods=('GET', 'POST'))
def show_items_in_order(order_id):
    if request.method == 'POST':
        datos = request.get_json()
        un_token = datos['access_token']
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        ahora = datetime.now()
        if token_encontrado is not None and token_encontrado.expires > ahora:
            listado=order_items_in_order_detailed(order_id)
            return jsonify(listado)
        else:
            return jsonify({'description': '', 'order_id': '', 'price': '', 'orderitem_id': '', 'name': '', 'quantity': 0, 'product_id': ''})
    else:
        return jsonify({'description': '', 'order_id': '', 'price': '', 'orderitem_id': '', 'name': '', 'quantity': 0, 'product_id': ''})


def order_items_in_order(order_id):
    listoi = []
    cant_orderitems = OrderItem.query.filter_by(order_id=order_id).count()
    if cant_orderitems > 0:
        resultadooi = OrderItem.query.filter_by(order_id=order_id)
        entryoi = resultadooi.all()
        for entry in entryoi:
            listoi.append({'orderitem_id': entry.orderitem_id,
                           'order_id': entry.order_id,
                           'product_id': entry.product_id,
                           'quantity': entry.quantity})
        return listoi
    else:
        listoi.append({'orderitem_id': '', 'order_id': '', 'product_id': '', 'quantity': 0})
        return listoi

def order_items_in_order_detailed(order_id):
    listoi = []
    cant_orderitems = OrderItem.query.filter_by(order_id=order_id).count()
    if cant_orderitems > 0:
        resultadooi = OrderItem.query.filter_by(order_id=order_id)
        entryoi = resultadooi.all()
        for entry in entryoi:
            producto_encontrado=Product.query.filter_by(product_id=entry.product_id).first()
            if producto_encontrado is not None:
                nombre=producto_encontrado.name
                descripcion = producto_encontrado.description
                listoi.append({'orderitem_id': entry.orderitem_id,
                               'order_id': entry.order_id,
                               'product_id': entry.product_id,
                               'name' : nombre,
                               'description' : descripcion,
                               'price': producto_encontrado.price,
                               'quantity': entry.quantity})
        return listoi
    else:
        listoi.append({'orderitem_id': 0,
                       'order_id': 0,
                       'product_id': 0,
                       'name' : '',
                       'description' : '',
                       'price': 0,
                       'quantity': 0})
        return listoi




###############################################  PRODUCT'S METHODS    ###############################################


def get_product_detail(product_id):
    producto_encontrado = Product.query.filter_by(product_id=product_id).first()
    if producto_encontrado is not None:
        return ({'product_id': producto_encontrado.product_id,
                 'name': producto_encontrado.name,
                 'description': producto_encontrado.description,
                 'price': producto_encontrado.price})

    else:
        return ({'product_id': 0,
                 'name': '',
                 'description': '',
                 'price': 0})

#############################################  PAGINATION AT CLIENT'S    ###############################################

@app.route('/api/productos', defaults={'page': 1}, methods=('GET', 'POST'))
@app.route('/api/productos/<int:page>', methods=('GET', 'POST'))
def show_productos(page):
    if request.method == 'POST':
        datos = request.get_json()
        un_token = datos['access_token']
        user_per_page = datos['per_page']
        user_page = datos['page']
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        ahora = datetime.now()
        if token_encontrado is not None and token_encontrado.expires > ahora:
            productos = get_products_for_page(user_page, user_per_page)
            return jsonify(productos)
        else:
            return jsonify({'name': '', 'description': '', 'price': ''})
    else:
        return jsonify({'name': '', 'description': '', 'price': ''})


####################### ADD A PRODUCT OR QUANTITY TO AN EXISTING AND NON PAID ORDER ####################################


#@app.route('/api/ordermod', defaults={'order_n': 1, 'prod_n': 1}, methods=('GET', 'POST', 'DELETE'))
@app.route('/api/ordermod/<int:order_n>/product/<int:prod_n>', methods=('GET', 'POST', 'DELETE'))
def add_product_order(order_n, prod_n):
    if request.method == 'DELETE':
        valor=-1
    if request.method == 'POST':
        valor=1
    datos = request.get_json()
    un_token = datos['access_token']
    token_encontrado = Token.query.filter_by(access_token=un_token).first()
    ahora = datetime.now()
    if token_encontrado is not None and token_encontrado.expires > ahora:
        usuario_encontrado = User.query.filter_by(id=token_encontrado.user_id).first()
        order_encontrado = Order.query.filter_by(order_id=order_n).first()
        if order_encontrado is not None:
            if order_encontrado.status=="Unpaid":
                orderitems=OrderItem.query.filter_by(product_id=prod_n).count()
                respuesta=add_product_in_order(order_n, prod_n,valor)
                return jsonify(respuesta)
            else:
                return jsonify({'order_id': 0, 'orderitem_id': 0, 'product_id': 0, 'quantity': 0})
        else:
            return jsonify({'order_id': 0, 'orderitem_id': 0, 'product_id': 0, 'quantity': 0})
    else:
        return jsonify({'order_id': 0, 'orderitem_id': 0, 'product_id': 0, 'quantity': 0})




def add_product_in_order(order_id,product_id, qty):
    order_encontrado = Order.query.filter_by(order_id=order_id).first()
    producto_encontrado = Product.query.filter_by(product_id=product_id).first()
    if order_encontrado is not None and producto_encontrado is not None:
        if qty != 0:
            orderitems = OrderItem.query.filter_by(order_id=order_encontrado.order_id).filter_by(product_id=product_id).count()
            if orderitems == 0 and qty>0:
                oitem = OrderItem(order_id=order_id, product_id=product_id, quantity=qty)
                un_id=oitem.orderitem_id
                db.session.add(oitem)
                db.session.commit()
                return {'orderitem_id': un_id, 'order_id': order_id, 'product_id': product_id, 'quantity': qty }
            elif orderitems>0 and qty>0:
                unorderitem = OrderItem.query.filter_by(order_id=order_encontrado.order_id).filter_by(product_id=product_id).first()
                val=unorderitem.quantity+qty
                unorderitem.quantity=val
                db.session.add(unorderitem)
                db.session.commit()
                return {'orderitem_id': unorderitem.orderitem_id, 'order_id': order_id, 'product_id': product_id, 'quantity': val}
            elif orderitems > 0 and qty < 0:
                unorderitem = OrderItem.query.filter_by(order_id=order_encontrado.order_id).filter_by(product_id=product_id).first()
                if unorderitem.quantity>=qty:
                    if (unorderitem.quantity + qty) >= 0:
                        val = unorderitem.quantity + qty
                        unorderitem.quantity = val
                    else:
                        val = 0
                    db.session.add(unorderitem)
                    db.session.commit()
                    return {'orderitem_id': unorderitem.orderitem_id, 'order_id': order_id, 'product_id': product_id,
                         'quantity': val}
                return {'orderitem_id': unorderitem.orderitem_id,
                                'order_id': unorderitem.order_id,
                                'product_id': unorderitem.product_id,  'quantity': unorderitem.quantity}

            return {'order_id': '1', 'user_id': '2', 'date': '3', 'status': '4'}
        elif qty==0:
            unorderitem = OrderItem.query.filter_by(order_id=order_encontrado.order_id).filter_by(product_id=product_id).first()
            return {'orderitem_id': unorderitem.orderitem_id,
                            'order_id': unorderitem.order_id,
                            'product_id': unorderitem.product_id, 'quantity': unorderitem.quantity}

    else:
        return {'orderitem_id': 0, 'order_id': 0,'product_id': 0,  'quantity': 0}





# @app.route('/api/productos/items', defaults={'page': 1} , methods=('GET','POST'))
# @app.route('/api/productos/items/<int:page>', methods=('GET','POST'))
# #@login_required
# def show_item(page):
#     if request.method == 'POST':
#         datos = request.get_json()
#         un_token = datos['access_token']
#         user_per_page = datos['per_page']
#         user_page = datos['page']
#         token_encontrado = Token.query.filter_by(access_token=un_token).first()
#         ahora=datetime.now()
#         if token_encontrado is not None and token_encontrado.expires > ahora:
#             productos = get_products_for_page(user_page, user_per_page)
#             return jsonify(productos)
#         else:
#             return jsonify({'order_id': '', 'date': '', 'status': ''})
#     else:
#             return jsonify({'order_id': '', 'date': '', 'status': ''})

#################################  DETAIL ON A SPECIFIC PRODUCT  #######################################################
@app.route('/api/productos/detail/<int:product_id>', methods=['POST'])
def show_product(product_id):
    if request.method == 'POST':
        datos = request.get_json()
        un_token = datos['access_token']
        token_encontrado = Token.query.filter_by(access_token=un_token).first()
        ahora = datetime.now()
        if token_encontrado is not None and token_encontrado.expires > ahora:
            productos = get_product_detail(product_id)
            return jsonify(productos)
        else:
            return jsonify({'product_id': '', 'name': '', 'description': '', 'price': ''})
    else:
        return jsonify({'product_id': '', 'name': '', 'description': '', 'price': ''})



############################################    INITILIZATION    #######################################################

@app.route('/')
def index():
    session.clear
    reg = User.query.count()
    on = 1
    cli = Client.query.count()
    return flask.render_template('index.html',REGISTERED=reg,ONLINE=on,CLIENTS=cli)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
