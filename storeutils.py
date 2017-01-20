from flask import Flask, url_for, render_template, redirect, request
import requests
import json
import os
from math import ceil
import urllib

#CLIENT_ID = '8fYXj1n3orTosTM1221uWYYmz1maiyjKmEm56uzE' #luciano
#CLIENT_SECRET = 'GkcauiqxiN9BpA5EScOxtw3CCzenOdKqci2LYEc4cRPNfAK2Vj' #luciano

API_KEY = ''
CLIENT_ID = '2JycAQbLawSXfPsBgk3WDXmZ9WuXPSVYhd9EKU9W' #anna
CLIENT_SECRET = '16n6kAQrSzDjb8TCuYxw9N1SADinxXu19YP51hl71teEVaeDlD' #anna

#REDIRECT_URI = 'http://localhost:5003/callback' #luciano
REDIRECT_URI = 'http://localhost:5004/callback' #anna

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
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    nombre = results['username']
    return nombre

def code_for_token(code):
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
    access_token = results['access_token']
    refresh_token = results['refresh_token']
    expires_in = results['expires_in']
    expires = results['expires']
    return (access_token, refresh_token,expires_in, expires)

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



# def code_for_token(code):
#     headers = {'content-type': 'application/json'}
#     url = "http://localhost:5000/api/token"
#     params = {
#         'code': code,
#         'client_id': CLIENT_ID,
#         'client_secret': CLIENT_SECRET,
#         'redirect_uri': REDIRECT_URI,
#         'grant_type': 'authorization_code'
#     }
#     r = requests.post(url, data=json.dumps(params), headers=headers)
#     results = json.loads(r.text)
#     access_token = results['access_token']
#     refresh_token = results['refresh_token']
#     expires_in = results['expires_in']
#     expires = results['expires']
#     return (access_token, refresh_token,expires_in, expires)


def query_orders(page, PER_PAGE,access_token):
    url = "http://localhost:5000/api/orders"
    params = {'access_token': access_token, 'page': page, 'per_page' : PER_PAGE}
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    return results

def query_items_in_order_detailed(order_id,access_token):
    url = "http://localhost:5000/api/orderdetail/"+str(order_id)
    params = {'access_token': access_token}
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    return results

def add_product_to_order(order_id,product_id,access_token,val):
    url = "http://localhost:5000/api/ordermod/"+str(order_id)+"/product/"+str(product_id)
    params = {'access_token': access_token}
    headers = {'content-type': 'application/json'}
    if val==1:
        r = requests.post(url, data=json.dumps(params), headers=headers)
    else:
        r = requests.delete(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    return results

def query_product_detail(product_id,access_token):
    url = "http://localhost:5000/api/productos/detail/"+str(product_id)
    params = {'access_token': access_token}
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    #print results
    return results

def query_products(page, PER_PAGE,access_token):
    url = "http://localhost:5000/api/productos"
    params = {'access_token': access_token, 'page': page, 'per_page' : PER_PAGE}
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    return results

def pay_order(order_id, access_token):
    url = "http://localhost:5000/api/order/"+str(order_id)+"/billing"
    params = {'access_token': access_token}
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    return results

def pool_server():
    url = "http://localhost:5000/api/ping"
    try:
        r = requests.post(url)
        results = json.loads(r.text)
    except requests.exceptions.ConnectionError:
        print "error in connection"
        results = {}
        results["answer"] = "offline"
        results["time"] = ""
    return results

def make_order(access_token):
    url = "http://localhost:5000/api/order"
    params = {'access_token': access_token}
    headers = {'content-type': 'application/json'}
    r = requests.post(url, data=json.dumps(params), headers=headers)
    results = json.loads(r.text)
    return results

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

