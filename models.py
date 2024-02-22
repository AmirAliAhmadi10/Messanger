from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Text, Boolean
from extensions import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_image = db.Column(db.String(20), nullable=False, default='default.jpg')

    contacts = db.relationship('User', secondary='contacts',
                               primaryjoin='User.id==Contact.user_id',
                               secondaryjoin='User.id==Contact.contact_id',
                               backref='contacts_list')

    groups = db.relationship('Group', backref='admin', lazy=True)
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

class Contact(db.Model):
    __tablename__ = 'contacts'
    user_id = Column(Integer, db.ForeignKey('user.id'), primary_key=True)
    contact_id = Column(Integer, db.ForeignKey('user.id'), primary_key=True)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='conversation', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)


    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=True)

    user = db.relationship('User', backref=db.backref('messages', lazy=True))
    group = db.relationship('Group', backref=db.backref('messages', lazy=True))

    def as_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'group_id': self.group_id,
            'current_username': self.user.username,
            'sender_first_name': self.user.first_name,
            'sender_last_name': self.user.last_name,
            'timestamp': self.timestamp.isoformat()
        }

    def __repr__(self):
        return f"Message('{self.content}', '{self.timestamp}')"

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    members = db.relationship('User', secondary='group_members',
                              backref='groups_joined', lazy=True)

class GroupMember(db.Model):
    __tablename__ = 'group_members'
    group_id = Column(Integer, db.ForeignKey('group.id'), primary_key=True)
    user_id = Column(Integer, db.ForeignKey('user.id'), primary_key=True)
    admin = Column(Boolean, nullable=False, default=False)
