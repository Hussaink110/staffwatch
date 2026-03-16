# server/wsgi.py
from click import command
import eventlet
eventlet.monkey_patch()

from app import app, socketio

if __name__ == "__main__":
    socketio.run(app)
    