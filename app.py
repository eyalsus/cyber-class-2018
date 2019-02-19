"""
SQL Injection
HTTP vs. HTTPS
Cookie SSO - steal cookies
XSS
"""
from flask import Flask, flash, redirect, redirect, url_for, render_template, request, session, abort, make_response
import pandas as pd
from sqlalchemy import create_engine
import traceback
import os
import hashlib

engine = create_engine('sqlite:///:memory:')
df = pd.DataFrame.from_dict([{'user_id': 1, 'user_name': 'alice', 'password': 'a'},
                             {'user_id': 2, 'user_name': 'bob', 'password': 'b'}])
df.to_sql(name='users', con=engine, if_exists='append', index=False)

df = pd.DataFrame.from_dict([{'user_name': 'Carry', 'tweet_message': 'Hi All :)'}])
df.to_sql(name='tweets', con=engine, if_exists='append', index=False)

QUERY_VERIFY_ACCOUNT = "select * from users where user_name = '{0}' and password = '{1}'"
QUERY_GET_PASSWORD_BY_USER = "select password from users where user_name = '{0}'"
HOME_DIR = '/home/dojo/PycharmProjects/flaskApp'
FAILED_LOGIN_ATTEMPTS = 'Failed login attempts'
timesVisited = 0
salt = 'magic_salt'

app = Flask(__name__)

@app.route("/")
def hello_db():
    df = pd.read_sql(sql='select * from users', con=engine)
    return str(df.head(10))

@app.route("/hello_without_template")
def hello_without_template():
    return "<h1>Hello World!</h1>"

@app.route("/hello_with_template/<string:name>")
def hello_with_template(name):
    return render_template('hello.html', name=name)

@app.route("/counter")
def counter():
    global timesVisited
    timesVisited += 1
    return "Hello #{0}".format(timesVisited)

@app.route("/tweet", methods=['POST'])
def handle_tweet():
    tweet_message = request.form.get('tweet_message')
    user_name = request.form.get('user_name')
    df = pd.DataFrame.from_dict([{'user_name': user_name, 'tweet_message': tweet_message}])
    df.to_sql(name='tweets', con=engine, if_exists='append', index=False)
    print df
    return redirect(url_for('login'))

@app.route("/login")
def login():
    sso_token = request.cookies.get('sso_token')
    user_name = request.cookies.get('user_name')
    print 'sso_token:', sso_token
    print 'user_name:', user_name
    if sso_token and user_name:
        query = QUERY_GET_PASSWORD_BY_USER.format(user_name)
        df = pd.read_sql(sql=query, con=engine)
        if len(df) > 0:
            password = df['password'][0]
            print user_name, password
            return render_template('welcome.html', user_name=user_name)

    df = pd.read_sql(sql='select * from tweets', con=engine)
    print df
    tweet_html = '<table><tr><td>user</td><td>tweet</td></tr>'
    print '*********************************'
    for index, row in df.iterrows():
        print '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
        print row['tweet_message']
        tweet_html += '<tr><td>{0}</td><td>{1}</td></tr>'.format(row['user_name'], row['tweet_message'])
    tweet_html += '</table>'
    print '+++++++++++++++++++++++++++++++++'
    return render_template('login.html', tweet_html=tweet_html)

@app.route("/verify_account", methods=['POST'])
def verify_account():
    resp = ''
    try:
        user_name = request.form.get('user_name')
        password = request.form.get('user_pass')
        query = QUERY_VERIFY_ACCOUNT.format(user_name, password)
        print query
        df = pd.read_sql(sql=query, con=engine)
        print 'df:\n', df
        if len(df) > 0:
            resp = make_response(render_template('welcome.html', user_name=user_name))
            resp.set_cookie(FAILED_LOGIN_ATTEMPTS, '', expires=0)
            if request.form.get('sso'):
                print 'remember password!!!'
                m = hashlib.md5()
                m.update(salt + user_name + password)
                sso_token = m.hexdigest()
                print 'sso_token:', sso_token
                resp.set_cookie('sso_token', str(sso_token))
                resp.set_cookie('user_name', str(user_name))
            else:
                print "don't remember password!!!"
        else:
            cookie_loginAttempts = request.cookies.get(FAILED_LOGIN_ATTEMPTS)
            loginAttempts = 0
            if cookie_loginAttempts:
                loginAttempts = int(cookie_loginAttempts)
            loginAttempts += 1

            resp = make_response(render_template('login.html'))
            resp.set_cookie(FAILED_LOGIN_ATTEMPTS, str(loginAttempts))
            print FAILED_LOGIN_ATTEMPTS, loginAttempts
    except:
        traceback.print_exc()
    return resp

if __name__ == "__main__":
    # app.run(host='127.0.0.1', port=443)
    app.run(host='127.0.0.1', port=443,
            ssl_context=(os.path.join(HOME_DIR,'cert.pem'), os.path.join(HOME_DIR,'key.pem')))

