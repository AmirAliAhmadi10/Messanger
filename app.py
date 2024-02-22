from flask import Flask
from flask_uploads import UploadSet, configure_uploads, IMAGES
from extensions import db, login_manager, bcrypt, migrate, socketio, Moment
import os
from routes import *
from models import User


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'AAAFCB'

    file_dir = os.path.dirname(__file__)
    db_route = os.path.join(file_dir, "app.db")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_route

    photos = UploadSet('photos', IMAGES)
    app.config['UPLOADED_PHOTOS_DEST'] = file_dir + '\\static\\profile_pics'
    configure_uploads(app, photos)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    socketio.init_app(app)
    moment = Moment(app)


    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()

    return app


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)
