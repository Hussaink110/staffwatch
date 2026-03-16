# server/wsgi.py
import eventlet
eventlet.monkey_patch()

from app import app, socketio

if __name__ == "__main__":
    socketio.run(app)
```

Then your Render start command becomes:
```
gunicorn --worker-class eventlet -w 1 --chdir server wsgi:app --bind 0.0.0.0:$PORT