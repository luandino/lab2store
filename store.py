import flask
from flask import Flask, url_for, render_template, redirect, request
from flask import session as login_session
import requests
import os
import sys
from flask import send_from_directory
from datetime import datetime, timedelta
from storeutils import pool_server, pay_order, make_order, add_product_to_order,query_items_in_order_detailed,query_orders
from storeutils import query_products, Pagination, query_product_detail
from storeutils import get_profile,refresh_token,code_for_token, auth_url
from flask_bootstrap import Bootstrap

from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

def create_app():
  app = Flask(__name__)
  Bootstrap(app)
  return app

import flaskr


#CAM = "http://grulicueva.homenet.org/~luciano/lab2store"


#CLIENT_ID = 'TRq20Yb5xutn9T8cjxU7MjlJRUrwqi0VwCevobaP' #luciano
#CLIENT_SECRET = 'u1pKCkRmd0QTWmww9v43a7zv8ymtNN6OdYdR5puO4ZviDCWZzI' #luciano


###CLIENT_ID = 'rCr4rtPXAhZcPJ8NqFLEVaX5UJJBQuJ90bqG1viK' #jose
###CLIENT_SECRET = 'yNoWbOya0zGG0yYCjSKChkA2sCsGuAOCdkemgLh9rhcstXMCf0' #jose
###SERVER_ADDR ="http://139.59.145.248" # DIGITALOCEAN 1 CPU
###API_KEY = ''
###CAM = ""

#CLIENT_ID = 'ISk23tJdGT7pZZpzrrPGq4n3jvf3M0TjpMbsxud3'         #anna 2cpu
#CLIENT_SECRET = '8ZIoI9qfErtwzDxnI5aZsw2cy0hO7v8QSQxcCqR1HwudjTbeh5'       #anna 2cpu
#SERVER_ADDR ="http://138.68.67.49" # DIGITALOCEAN 2 CPU


#CLIENT_ID = 'l7ePTstSGglimGHhpE2Ogtks3KkCa5jzk8Vj2qQ1' #peter
#CLIENT_SECRET = '5VUhu0AglAJozVGTtcXb8Um6sfInMvU6Y1c6kSYCsqWZEQ6Whl' #peter




#SERVER_ADDR ="http://localhost:5000"

app = Flask(__name__)
app.config.from_object(__name__)



app.secret_key = 'twtrtretrefsdgfgvbcvbbvbcviutiujgkhj'




############################################################################################################

#print os.environ['PAT']
#print os.environ['HOME']
#import sys
#print sys.home


#app.config['PAT'] = os.environ.get('PAT','default si no existe')
#print app.config['HISTSIZE']
#print os.environ.get('ENVIRO', 'defaeeult si no existe')#

app.config.from_envvar('ENVIRO', silent=True)

#REDIRECT_URI = app.config['CAMINO']+'callback' #luciano

SERVER_ADDR=app.config['SERVER_ADDR']
CAM=app.config['CAMINO']
CLIENT_ID = app.config['CLIENT_ID']
CLIENT_SECRET = app.config['CLIENT_SECRET']

#print REDIRECT_URI
### AS I RECEIVED A WARNING OF LACK OF FAVICON, I CREATE ONE AND PUT IN THE PATH ###

def url_for_other_page(page):
    args = request.view_args.copy()
    args['page'] = page
    return url_for(request.endpoint, **args)
app.jinja_env.globals['url_for_other_page'] = url_for_other_page

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')






#####################################  HERE FUNCTIONS ###########################################



PER_PAGE = 10

@app.route('/productos', defaults={'page': 1})
@app.route('/productos/<int:page>')
def show_products(page):
    token=login_session.get('access_token')
    productos = query_products(page, PER_PAGE,token)
    arrayurls = []
    if not productos and page != 1:
        print "nothing"
        #abort(404)
    count=200
    if page ==1:
        inicio=1
        fin=PER_PAGE
    else:
        inicio=page*PER_PAGE
        fin=inicio+PER_PAGE
    for i in range(inicio,fin):
        url_product="http://flask-enviroment.z2spn3xrd3.us-west-2.elasticbeanstalk.com/api/product/item/"+str(i)
        arrayurls.append({'url': url_product})
    pagination = Pagination(page, PER_PAGE, count)

    return render_template('productsu.html', pagination=pagination, products=productos, urls=arrayurls, CAMINO=CAM )


#####################################  HERE FUNCTIONS ###########################################



### HOMEPAGE  ###
@app.route('/')
def index():
    results = pool_server()
    result = results['answer']
    if result == "offline":
        img = "status_offline.gif"
    elif result == "OK":
        img = "server_online.gif"


    return flask.render_template('indexoff.html', CAMINO=CAM, url=auth_url(), WHO="Guest", IMG=img)







####################################################################################################################


@app.route('/order')
def makeanorder():
    if login_session.get('access_token') is None:
        return redirect(url_for("index"))
    tk = login_session['access_token']
    order=make_order(tk)
    return flask.render_template('orderu.html', NUMORDER=order["order"], FECHA=order["date"], CAMINO=CAM)

@app.route('/orderdetail', defaults={'order_id': 1})
@app.route('/orderdetail/<int:order_id>')
def orderdetail(order_id):
    token=login_session.get('access_token')
    print "token es"
    print token
    print "order id es"
    print order_id
    if token is not None:
        itemlist = query_items_in_order_detailed(order_id,token)
        suma = 0
        print "item"
        print itemlist[0]['product_id']
        if itemlist[0]['product_id'] == 0 or itemlist[0]['product_id'] is None:
            itemlist=""
        else:
            for item in itemlist:
                suma=item['quantity']*item['price']+suma
        return render_template('orderdetail.html', items=itemlist, order=order_id, price=suma, CAMINO=CAM)
    else:
        return "token no llego"



@app.route('/orderdetail/<int:order_id>/<string:val>/<int:product_id>')
def addproduct_to_order(order_id,product_id,val):
    token=login_session.get('access_token')
    if val=="add":
        valor=1
    else:
        valor=0
    resu=add_product_to_order(order_id,product_id,token,valor)
    url=CAM+"/orderdetail/"+str(order_id)
    return redirect(url)

PPER_PAGE_ORDER = 4

@app.route('/orderlist', defaults={'page': 1})
@app.route('/orderlist/<int:page>')
def show_order(page):
    token=login_session.get('access_token')
    orders = query_orders(page, PER_PAGE,token)
    arrayurls = []
    if not orders and page != 1:
        print "nothing"
        #abort(404)
    count=200
    if page ==1:
        inicio=1
        fin=PPER_PAGE_ORDER
    else:
        inicio=page*PPER_PAGE_ORDER
        fin=inicio+PPER_PAGE_ORDER
    for i in range(inicio,fin):
        url_order=SERVER_ADDR+str(i)
        arrayurls.append({'url': url_order})
    pagination = Pagination(page, PPER_PAGE_ORDER, count)
    return render_template('ordersu.html', pagination=pagination, orders=orders, urls=arrayurls, CAMINO=CAM )

@app.route('/payorder', methods=['POST'])
def payorder():
    token = login_session.get('access_token')
    if request.method == 'POST':
        order_id = request.form.get('order_id')
        resu = pay_order(order_id, token)
        url = CAM+"/orderlist"
        return redirect(url)

#######################################################################################################################

@app.route('/addnewproduct', methods=['POST'])
def addnewproduct_to_order():
    token=login_session.get('access_token')
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        order_id = request.form.get('order_id')
        product_id=int(product_id)
        print "product"
        print product_id
        print "order"
        print order_id
        if type(product_id) == int:
            resu=add_product_to_order(order_id,product_id,token,1)
        url=CAM+"/orderdetail/"+str(order_id)
        print "veamos url"
        print url
        return redirect(url)

@app.route('/productos/item', defaults={'product_id': 1})
@app.route('/productos/item/<int:product_id>')
def productdetail(product_id):
    token = login_session.get('access_token')
    itemlist = query_product_detail(product_id, token)
    #print "itelmlis"
    #print itemlist['price']
    return render_template('productdetu.html', price=itemlist['price'], product_id=itemlist['product_id'],
                           name=itemlist['name'], description=itemlist['description'], CAMINO=CAM )

#######################################################################################################################


#####################################################################################################################
@app.route('/me')
def askaboutme():
    if login_session.get('access_token') is None:
        return redirect(url_for("index"))
    tk = login_session['access_token']
    unnombre=get_profile(tk)
    exp=login_session['expira']
    ahora=datetime.now()
    if exp > ahora:
        sta = "Valid"
    else:
        sta = "Expired"
    return flask.render_template('usersu.html', USERNAME=unnombre, EXPIRE=exp, STATUS=sta, CAMINO=CAM)

@app.route('/ping')
def ping():
    results = pool_server()
    result=results['answer']
    if result=="offline":
        img = "status_offline.gif"
    elif result=="OK":
        img = "server_online.gif"

    return flask.render_template('indexoff.html', url=auth_url(), WHO="Guest", IMG=img, CAMINO=CAM)

@app.route('/logout')
def logout():
    login_session.clear()
    return redirect(url_for("index"))


@app.route('/callback')
def callback():
    args = flask.request.args
    if args.get('error', None):
        return "Authentication error: {0}".format(args['error'])
    code = args.get('code', None)
    user = args.get('user', None)
    if not code:
        return "Authentication error: no code provided"
    tokens = code_for_token(code)
    acc_token = tokens[0]
    login_session['access_token'] = acc_token
    ref_token = tokens[1]
    expira = tokens[3]
    ahora=datetime.now()
    expiral = datetime(int(expira[0]),int(expira[1]),int(expira[2]),int(expira[3]),int(expira[4]),int(expira[5]))
    user=get_profile(acc_token)
    login_session['expira'] = expiral
    if expiral > ahora:
        estado = "Valid"
    else:
        estado = "Deprecated"
    return render_template("indexu.html", NOW=ahora,WHO=user, STATUS=estado, EXPIRES=expiral, CAMINO=CAM)

if __name__ == '__main__':

    app.run(host='127.0.0.1', port=5003)