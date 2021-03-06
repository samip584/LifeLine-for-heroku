from LifeLineServer import app, socket

# Runserver
if __name__ == "__main__":
    socketio.run(app)
    # app.run(debug=True)
