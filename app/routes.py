from flask import render_template, flash, redirect, url_for, request, session
from app import app
from app.forms import LoginForm
from flask_login import current_user, login_user, login_required, logout_user
from app.models import User
from werkzeug.urls import url_parse
from app import db
from app.forms import RegistrationForm
from stellar_sdk import Server, Asset, Account, Keypair, TransactionBuilder, Network
from stellar_sdk.exceptions import NotFoundError, BadResponseError, BadRequestError
import requests
import os

app.config['SESSION_TYPE'] = 'filesystem'


# Accounts endpoint - get info about an account.
accounts_url = 'https://horizon-testnet.stellar.org/accounts/{}'
# Interact with test net.
server = Server(horizon_url='https://horizon-testnet.stellar.org')
# URL for path endpoint - find path from x to y.
path_url = 'https://horizon-testnet.stellar.org/paths/strict-send?destination_assets={}%3A{}&source_asset_type=native&source_amount={}'

@app.route('/')
@app.route('/index')
@login_required
def index():
    user = {'username' : 'User'}
    transactions = [
        {
            'author' : { 'username' : 'John'},
            'body' : 'Licence payment on XYZ'
        },
        {
            'author' : { 'username' : 'Susan'},
            'body' : 'Licence payment on IJK'
        }
    ]
    return render_template('index.html', title='Home', transactions=transactions)

@app.route('/services')
@login_required
def services():
    return render_template('services.html', title='Services')

def load_last_paging_token():
    return "now"

def save_paging_token(paging_token):
    pass

@app.route('/wallet', methods=['GET', 'POST'])
@login_required
def wallet():
    pub_key = ''
    get_transaction = ''
    json_obj = ''
    if request.method == 'POST':
        if request.form.get("submit_key") == 'Submit':
            pub_key = request.form['pubkey']
            session['pub_key'] = pub_key
        else:
            pub_key = session.get('pub_key', None)
        # get information from Horizon accounts end point
        r = requests.get(accounts_url.format(pub_key))
        json_obj = r.json()
        session['balances'] = json_obj
        print(pub_key)
        if request.form.get("get_transaction") == 'Get transactions':
            print("enter get transaction\n")
            account_id = "GCEWVURVUOUL5545BHQYQRF6BONMDAA77IKVTODVI5DNMDXSKBYITR3Z"
            payments = server.payments().for_account(account_id)
            last_token = load_last_paging_token()
            print("Last token: " + last_token + "\n")
            if last_token:
                payments.cursor(last_token)
                print("Payment cursor: " + str(payments.cursor(last_token)) + "\n")
                print("Entering payment loop \n")
            for payment in payments.stream():
                save_paging_token(payment["paging_token"])
                print("Payment type:" + payment['type'] + "\n")
                if payment["type"] != "payment":
                    continue
                if payment['to'] != account_id:
                    continue
                if payment["asset_type"] == "native":
                    asset = "Lumens"
                else:
                    asset = f"{payment['asset_code']}:{payment['asset_issuer']}"
                print("Get transaction:\n")
                get_transaction = (f"{payment['amount']} {asset} from {payment['from']}")
                print(get_transaction)
                if(get_transaction != ''):
                    break

    return render_template('wallet.html', title="Wallet", pub_key=pub_key, json_obj=json_obj, get_transaction=get_transaction)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign in', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Succesfully registered!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)