#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, url_for, request, redirect, \
    flash, make_response, jsonify
import random
import string
import os
import httplib2
import json
import numbers
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.utils import secure_filename
import requests

# Oauth

from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

# Database

from database_setup import Base, Category, Item, User
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

ALLOWED_EXTENSIONS = set(['svg', 'png', 'jpg', 'jpeg', 'gif'])
APP_ROOT= os.path.abspath(os.path.dirname(__name__))
UPLOAD_FOLDER = os.path.join(APP_ROOT,"static\img")
# Oauth

CLIENT_ID = \
    '521849747297-tsmjigl9a81ap061aotk61v1117l77u1.apps.googleusercontent.com'
CLIENT_SECRET = 'qVUT-BiDQhktN_gA4nL9Eb-B'

app = Flask(__name__)


# Returns the extension of a file

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() \
        in ALLOWED_EXTENSIONS


# Check if the argument is a number or not

def is_number(number):
    try:
        float(number)
    except ValueError:
        return False
    return True


# ------------Login---------- #

@app.route('/login/')
def showLogin():
    if 'username' in login_session:
        return redirect(url_for('showCategory'))
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect/<state>/', methods=['POST'])
def gconnect(state):

    # Validate state token

    if state != login_session['state']:
        response = make_response(
            json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code

    code = request.data

    try:

        # Upgrade the authorization code into a credentials object

        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = \
            make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        % access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = \
            make_response(
                json.dumps(
                    "Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.

    if result['issued_to'] != CLIENT_ID:
        response = \
            make_response(
                json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(
                json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    users = session.query(User).all()

    # If the user wants to signup

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    users = session.query(User).all()
    for user in users:
        if user.email == login_session['email']:
            return 'OK'
    user = User(name=login_session['username'],
                email=login_session['email'])
    session.add(user)
    session.commit()
    return 'OK'


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = \
            make_response(json.dumps('Current user not connected.'),
                          401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('showCategory'))
    else:
        response = \
            make_response(
                json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# ------------ JSON Endpoints ---------- #

@app.route('/category/json')
def showCategoryJSON():
    if 'username' not in login_session:
        return redirect(url_for('showCategory'))
    category = session.query(Category).all()
    json = jsonify(Category=[c.serialize for c in category])
    response = make_response(json, 200)
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/<int:category_id>/json')
def showMenuItemJSON(category_id):
    items = session.query(Item).filter_by(category_id=category_id)
    json = jsonify(Item=[i.serialize for i in items])
    response = make_response(json, 200)
    response.headers['Content-Type'] = 'application/json'
    return response


# ------------ Category Routes ---------- #

@app.route('/')
@app.route('/category')
def showCategory():
    categories = session.query(Category).order_by('name').all()
    return render_template('home.html', categories=categories)


# ------------ Add Category  ---------- #

@app.route('/category/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect(url_for('showCategory'))

    if request.method == 'POST':

        # Input Validation

        if request.form['name'] == '':
            flash('Please Insert a Name')
            return redirect(request.url)

    # check if the post request has the file part

        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))

        category = Category(name=request.form['name'], picture = filename )
        session.add(category)
        session.commit()
        flash('Category ' + ' ' + category.name + ' ' + ' created.')
        return redirect(url_for('showCategory'))
    else:
        return render_template('category-new.html', view='newCategory')


# ------------ Edit Category  ---------- #

@app.route('/category/edit/<int:category_id>', methods=['GET', 'POST'])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect(url_for('showCategory'))
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':

        # Input Validation

        if request.form['name'] == '':
            flash('Please Insert a Name')
            return redirect(request.url)
        category.name = request.form['name']

        session.add(category)
        session.commit()
        flash('Category ' + ' ' + category.name + ' ' + ' updated.')
        return redirect(url_for('showCategory'))
    else:
        return render_template(
            'category-edit.html', view='editCategory', category=category)


# ------------ Delete Category  ---------- #

@app.route('/category/delete/<int:category_id>', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect(url_for('showCategory'))
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash('Category ' + ' ' + category.name + ' ' + ' deleted.')
        return redirect(url_for('showCategory'))
    else:
        return render_template('category-delete.html',
                               view='deleteCategory', category=category)


# --------------------- Item Routes ------------------------- #

@app.route('/<int:category_id>/item')
def showItem(category_id):
    items = \
        session.query(Item).filter_by(
            category_id=category_id).order_by('name').all()

    return render_template('item-list.html', items=items,
                           category_id=category_id)


# ------------ Add Item  ---------- #

@app.route('/<int:category_id>/item/new', methods=['GET', 'POST'])
def newItem(category_id):
    if 'username' not in login_session:
        return redirect(url_for('showCategory'))
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':

        # Input Validation

        if request.form['name'] == '':
            flash('Please Insert a Name')
            return redirect(request.url)

        if request.form['price'] == '' or not is_number(request.form['price']):
            flash('Please Insert a Valid Price')
            return redirect(request.url)

        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))

        user = session.query(User).filter_by(
            email=login_session['email']).one()

        item = Item(name=request.form['name'], 
                    category_id=category_id,
                    price=request.form['price'],
                    picture=filename,
                    description=request.form['description'],
                    user_id=user.id)
        session.add(item)
        session.commit()
        flash('Item ' + ' ' + item.name + ' ' + ' created.')
        return redirect(url_for('showItem', category_id=category.id))
    else:
        return render_template('item-new.html', category=category)


# ------------ Edit Item  ---------- #

@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(item_id):
    if 'username' not in login_session:
        return redirect(url_for('showCategory'))
    item = session.query(Item).filter_by(id=item_id).one()
    category = \
        session.query(Category).filter_by(id=item.category_id).one()
    if request.method == 'POST':

        # Input Validation

        if request.form['name'] == '':
            flash('Please Insert a Name')
            return redirect(request.url)

        if request.form['price'] == '' or is_number(request.form['price']) == False:
            flash('Please Insert a Valid Price')
            return redirect(request.url)

        item.name = request.form['name']
        item.description = request.form['description']
        item.price = request.form['price']

        session.add(item)
        session.commit()
        flash('Item ' + ' ' + item.name + ' ' + ' updated.')
        return redirect(url_for('showItem',
                        category_id=item.category_id))
    else:
        return render_template('item-edit.html', item=item,
                               category=category)


# ------------ Delete Item  ---------- #

@app.route('/category/delete/<int:item_id>/delete', methods=['GET',
           'POST'])
def deleteItem(item_id):
    if 'username' not in login_session:
        return redirect(url_for('showCategory'))
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item ' + ' ' + item.name + ' ' + ' deleted.')
        return redirect(url_for('showItem',
                        category_id=item.category_id))
    else:
        return render_template('item-delete.html', item=item)

if __name__ == '__main__':
    app.secret_key = 'you_dont_know_me'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
