from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from flask_session import Session
from stellar_sdk import Server, Asset, Account, Keypair, TransactionBuilder, Network

### flask app section
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

bootstrap = Bootstrap(app)

### stellar integration section


from app import routes, models