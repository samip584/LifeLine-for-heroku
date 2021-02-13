from LifeLineServer.controllers.traffic import *
from LifeLineServer.controllers.driver import *
from LifeLineServer import driver_db, traffic_db


# Get single traffics
@app.route('/installDB', methods=['GET'])
# @token_required
def installDB():
  driver_db.create_all()
  traffic_db.create_all()
  return jsonify({'message': 'DataBase initiated'})
