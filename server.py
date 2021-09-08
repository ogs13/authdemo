import hmac
import json
import base64
import hashlib
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()
SECRET_KEY = '53c67ba546a109ecfadcaf8fecde4a06f43c22cc0fe41a9a7bae88ad8935b987'
PASSWORD_SALT = '29eaa805ac9d9a0b60535872d6e9d6e8ff90a357962de235469489b9f73e7ffc'
users = {
    'genady@user.com':{
        'name':'Genady',
        #'password':'password_1',
        'password':'9edcfecc89cc42b3de74616bfee7d9321f7ea05a04730a612fb045a2f58f9ed8',
        'balance':100000,
    },
    'petr@user.com':{
        'name':'Petr',
        #'password':'password_2',
        'password':'8a895a6789f672c4fc9303bf1c0a1e3667a2bd23769e065a2209cd6379255ee6',
        'balance':1000,
    },
}

def sign_data(data: str) -> str:
    '''возвращает подписанные данные'''
    return hmac.new(SECRET_KEY.encode(),
    msg=data.encode(),
    digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed:str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign,sign):
        return username

def verify_password(username: str, password: str) -> bool:
    
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode())\
        .hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return stored_password_hash == password_hash

@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html','r') as f:
        login_page = f.read()
    
    if not username:
       return Response(login_page,media_type='text/html')
    
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}! </br> Баланс: {users[valid_username]['balance']}$",
        media_type='text/html')


'''@app.post('/login')
def process_login_page(username: str=Form(...), password: str=Form(...)):
    #FormData
    user = users.get(username)
    #if not user or user['password'] != password:
    if not user or not verify_password(username, password):
        #return Response('Unknown user',media_type='text/html')
        return Response(
            json.dumps({
                'success':False,
                'message':'Unknown user'
            }),
            media_type='application/json')
    
    fstr = f"HELLO {user['name']}!<br/>Баланс: {user['balance']}$"
    #response = Response(fstr,media_type='text/html')
    response = Response(
        json.dumps({
            'success':True,
            'message':fstr
        }),
        media_type='application/json',
    )
    username_to_bytes = f'{base64.b64encode(username.encode()).decode()}'
    username_signed = f'{username_to_bytes}.{sign_data(username)}'
    #response.set_cookie(key='username',value=username)
    response.set_cookie(key='username',value=username_signed)
    return response'''

@app.post('/login')
def process_login_page(data: dict = Body(...)):
    #JSON
    print('data is ', data)
    username = data['username']
    password = data['password']
    user = users.get(username)
    #if not user or user['password'] != password:
    if not user or not verify_password(username, password):
        #return Response('Unknown user',media_type='text/html')
        return Response(
            json.dumps({
                'success':False,
                'message':'Unknown user'
            }),
            media_type='application/json')
    
    fstr = f"HELLO {user['name']}!<br/>Баланс: {user['balance']}$"
    #response = Response(fstr,media_type='text/html')
    response = Response(
        json.dumps({
            'success':True,
            'message':fstr
        }),
        media_type='application/json',
    )
    username_to_bytes = f'{base64.b64encode(username.encode()).decode()}'
    username_signed = f'{username_to_bytes}.{sign_data(username)}'
    #response.set_cookie(key='username',value=username)
    response.set_cookie(key='username',value=username_signed)
    return response

