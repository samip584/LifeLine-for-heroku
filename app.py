from LifeLineServer import app, socket

# Runserver
if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)
    # app.run(debug=True)
