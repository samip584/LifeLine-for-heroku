from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os


# Init app
app = Flask(__name__)
CORS(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'buzzgopa'
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://bzaayrszcpxigd:fc04129768348936a0687b4931fb96414c6452430495e0a9bd855717f43cd9d1@ec2-52-6-178-202.compute-1.amazonaws.com:5432/de039mjiokhkbg'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

socket = SocketIO(app = app, cors_allowed_origins='*')

# Init driver_db
driver_db = SQLAlchemy(app)
# Init ma
driver_ma = Marshmallow(app)
# Init traffic_db
traffic_db = SQLAlchemy(app)
# Init traffic_ma
traffic_ma = Marshmallow(app)



from LifeLineServer import routes
from LifeLineServer import projectsocket