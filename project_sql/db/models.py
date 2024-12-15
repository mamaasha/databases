# db/models.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from db.config import DATABASE_URL
from datetime import datetime, timezone
from enum import Enum
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate

db = SQLAlchemy()

class UserRole(Enum):
    USER = 'USER'
    EDITOR = 'EDITOR'
    ADMIN = 'ADMIN'

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)

    slides = db.relationship('Slide', backref='user', lazy=True)
    presentations = db.relationship('Presentation', backref='user', lazy=True)
    search_results = db.relationship('SearchResult', backref='user', lazy=True)
    logs = db.relationship('Log', backref='user', lazy=True)
    errors = db.relationship('Error', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    __tablename__ = 'categories'
    category_id = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(255), nullable=False)

    slides = db.relationship('Slide', backref='category', lazy=True)

class SlideTypeEnum(Enum):
    CASE = 'case'
    TITLE = 'title'
    OTHER = 'other'

class Presentation(db.Model):
    __tablename__ = 'presentations'
    presentation_id = db.Column(db.Integer, primary_key=True)
    google_slide_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    created_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))

    slides = db.relationship('Slide', backref='presentation')

class Slide(db.Model):
    __tablename__ = 'slides'
    slide_id = db.Column(db.Integer, primary_key=True)
    presentation_id = db.Column(db.Integer, db.ForeignKey('presentations.presentation_id'), nullable=False)
    topic = db.Column(db.String(100))
    industry = db.Column(db.String(100))
    slide_type = db.Column(db.Enum(SlideTypeEnum))
    added_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    added_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    category_id = db.Column(db.Integer, db.ForeignKey('categories.category_id'))

class SearchResult(db.Model):
    __tablename__ = 'search_results'
    result_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    search_query = db.Column(db.Text, nullable=False)
    result_slides = db.Column(db.JSON)
    search_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    duration = db.Column(db.Float)

class LogLevel(Enum):
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'

class Log(db.Model):
    __tablename__ = 'logs'
    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    action = db.Column(db.String(255))
    details = db.Column(db.Text)
    log_level = db.Column(db.Enum(LogLevel))
    log_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class ErrorLevel(Enum):
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'

class Error(db.Model):
    __tablename__ = 'errors'
    error_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    error_message = db.Column(db.String(500))
    error_level = db.Column(db.Enum(ErrorLevel))
    error_date = db.Column(db.DateTime, default=datetime.now(timezone.utc))

if __name__ == '__main__':
    db.create_all()
    print("Все таблицы успешно созданы!")
