from flask import Flask, request, jsonify
import pandas as pd
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from db.models import (
    db, User, Category, Slide, Presentation,
    SearchResult, Log, Error, UserRole,
    SlideTypeEnum, LogLevel, ErrorLevel
)
from db.config import DATABASE_URL, JWT_SECRET_KEY
from flask_migrate import Migrate
from datetime import timedelta, datetime
from functools import wraps
from flask import abort
import os
import subprocess
from sqlalchemy import text
from concurrent.futures import ThreadPoolExecutor
import psycopg2
from psycopg2 import sql
import matplotlib.pyplot as plt
from io import BytesIO

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=25)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app)

executor = ThreadPoolExecutor(max_workers=10)

from flask_jwt_extended.exceptions import JWTExtendedException
from werkzeug.exceptions import HTTPException

@app.errorhandler(JWTExtendedException)
def handle_jwt_error(e):
    return jsonify({"msg": str(e)}), 422

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    return jsonify({"msg": e.description}), e.code

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({"msg": f"Неизвестная ошибка: {str(e)}"}), 500

@app.before_request
def log_request_info():
    app.logger.debug(f"Headers: {request.headers}")
    app.logger.debug(f"Body: {request.get_data()}")

def async_task(func, *args, **kwargs):
    executor.submit(func, *args, **kwargs)

from flask_jwt_extended import get_jwt

def role_required(required_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            try:
                claims = get_jwt()
                role = claims.get('role', None)
                app.logger.debug(f"JWT Claims: {claims}")
                app.logger.debug(f"User Role: {role}")
                if role not in required_roles:
                    app.logger.warning(f"Недостаточно прав: Требуется роль {required_roles}, а у пользователя {role}")
                    return jsonify({"msg": "Недостаточно прав"}), 403
                return fn(*args, **kwargs)
            except Exception as e:
                app.logger.error(f"Ошибка в декораторе role_required: {e}")
                return jsonify({"msg": "Неизвестная ошибка"}), 500
        return wrapper
    return decorator


def register_user(username, password, role):
    if User.query.filter_by(username=username).first():
        return {"msg": "Пользователь уже существует"}, 409

    if role not in UserRole.__members__:
        return {"msg": "Недопустимая роль"}, 400

    new_user = User(username=username, role=UserRole[role])
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return {"msg": "Пользователь зарегистрирован успешно"}, 201

# Регистрация
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'USER').upper()  # По умолчанию USER

    if not username or not password:
        return jsonify({"msg": "Имя пользователя и пароль обязательны"}), 400

    if role not in UserRole.__members__:
        return jsonify({"msg": "Недопустимая роль"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Пользователь уже существует"}), 409

    new_user = User(username=username, role=UserRole[role])
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "Пользователь зарегистрирован успешно"}), 201

# Логин пользователя -> JWT токен
def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return {"msg": "Неверные имя пользователя или пароль"}, 401

    access_token = create_access_token(identity=user.username, additional_claims={'role': user.role.value})

    return {"access_token": access_token}, 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Имя пользователя и пароль обязательны"}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"msg": "Неверные имя пользователя или пароль"}), 401

    access_token = create_access_token(identity=user.username, additional_claims={'role': user.role.value})
    return jsonify({"access_token": access_token}), 200

# Информация о пользователе
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()  # Это строка (username)
    claims = get_jwt()
    role = claims.get('role', None)
    if not current_user:
        return jsonify({"msg": "Не авторизован"}), 401
    return jsonify(logged_in_as={'username': current_user, 'role': role}), 200

# Получение списка презентаций
@app.route('/presentations', methods=['GET'])
@jwt_required()
def get_presentations():
    presentations = Presentation.query.all()
    result = []
    for pres in presentations:
        result.append({
            "presentation_id": pres.presentation_id,
            "google_slide_id": pres.google_slide_id,
            "name": pres.name,
            "created_date": pres.created_date.isoformat(),
            "created_by": pres.created_by
        })
    return jsonify(result), 200

# Добавление новой презентации
@app.route('/presentations', methods=['POST'])
@jwt_required()
@role_required(['ADMIN', 'EDITOR'])
def add_presentation():
    data = request.get_json()
    google_slide_id = data.get('google_slide_id')
    name = data.get('name')
    
    if not google_slide_id or not name:
        return jsonify({"msg": "Недостаточно данных для создания презентации"}), 400

    username = get_jwt_identity()  # Теперь это строка
    if not username:
        return jsonify({"msg": "Не авторизован"}), 401
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "Пользователь не найден"}), 404
    created_by = user.user_id

    if Presentation.query.filter_by(google_slide_id=google_slide_id).first():
        return jsonify({"msg": "Презентация с таким google_slide_id уже существует"}), 409
    
    def db_task():
        try:
            query = text("INSERT INTO presentations (google_slide_id, name, created_by) VALUES (:google_slide_id, :name, :created_by)")
            params = { "google_slide_id": google_slide_id, "name": name, "created_by": created_by }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Презентация добавлена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при добавлении презентации: {e}")
    
    async_task(db_task)
    return jsonify({"msg": "Презентация добавлена успешно"}), 201

# Обновление презентации
@app.route('/presentations/<int:presentation_id>', methods=['PUT'])
@jwt_required()
@role_required(['ADMIN', 'EDITOR'])
def update_presentation(presentation_id):
    presentation = Presentation.query.get_or_404(presentation_id)
    data = request.get_json()
    current_user = get_jwt_identity()
    username = current_user  # Присваиваем напрямую
    if not username:
        return jsonify({"msg": "Не авторизован"}), 401
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "Пользователь не найден"}), 404
    created_by = user.user_id

    def db_task():
        try:
            query = text("""
                UPDATE presentations 
                SET google_slide_id = :google_slide_id, 
                    name = :name, 
                    created_by = :created_by 
                WHERE presentation_id = :presentation_id
            """)
            params = {
                "google_slide_id": data.get('google_slide_id', presentation.google_slide_id),
                "name": data.get('name', presentation.name),
                "created_by": created_by,
                "presentation_id": presentation_id
            }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Презентация обновлена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при обновлении презентации: {e}")
    
    async_task(db_task)
    return jsonify({"msg": "Презентация обновлена успешно"}), 200

# Удаление презентации
@app.route('/presentations/<int:presentation_id>', methods=['DELETE'])
@role_required(['ADMIN'])
def delete_presentation(presentation_id):
    def db_task():
        try:
            query = text("DELETE FROM presentations WHERE presentation_id = :presentation_id")
            params = {"presentation_id": presentation_id}
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Презентация удалена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при удалении презентации: {e}")
    async_task(db_task)
    return jsonify({"msg": "Презентация удалена успешно"}), 200

# Получение списка слайдов
@app.route('/slides', methods=['GET'])
@jwt_required()
def get_slides():
    try:
        slides = Slide.query.all()
        result = []
        for slide in slides:
            result.append({
                "slide_id": slide.slide_id,
                "presentation_id": slide.presentation_id,  
                "topic": slide.topic,
                "industry": slide.industry,
                "slide_type": slide.slide_type.value if slide.slide_type else None,
                "added_date": slide.added_date.isoformat(),
                "added_by": slide.added_by,
                "category_id": slide.category_id
            })
        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Неизвестная ошибка: {e}")
        return jsonify({"msg": f"Неизвестная ошибка: {str(e)}"}), 500

# Добавление нового слайда
@app.route('/slides', methods=['POST'])
@role_required(['ADMIN', 'EDITOR'])
def add_slide():
    data = request.get_json()
    presentation_id = data.get('presentation_id')
    topic = data.get('topic')
    industry = data.get('industry')
    slide_type = data.get('slide_type')
    added_by = data.get('added_by')
    category_id = data.get('category_id')

    if Slide.query.filter_by(presentation_id=presentation_id, topic=topic).first():
        return jsonify({"msg": "Слайд с такими данными уже существует"}), 409

    if slide_type not in SlideTypeEnum.__members__:
        return jsonify({"msg": "Недопустимый тип слайда"}), 400
    
    def db_task():
        try:
            query = text("INSERT INTO slides (presentation_id, topic, industry, slide_type, added_by, category_id) VALUES (:presentation_id, :topic, :industry, :slide_type, :added_by, :category_id)")
            params = {
                    "presentation_id": presentation_id,
                    "topic": topic,
                    "industry": industry,
                    "slide_type": slide_type,
                    "added_by": added_by,
                    "category_id": category_id
                }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Слайд добавлен успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при добавлении слайда: {e}")
    async_task(db_task)
    return jsonify({"msg": "Слайд добавлен успешно"}), 201

# Обновление существующего слайда
@app.route('/slides/<int:slide_id>', methods=['PUT'])
@role_required(['ADMIN', 'EDITOR'])
def update_slide(slide_id):
    slide = Slide.query.get_or_404(slide_id)
    data = request.get_json()
    slide_type = data.get('slide_type')

    if slide_type and slide_type not in SlideTypeEnum.__members__:
        return jsonify({"msg": "Недопустимый тип слайда"}), 400

    def db_task():
        try:
            query = text("""
                UPDATE slides 
                SET presentation_id = :presentation_id, 
                    topic = :topic, 
                    industry = :industry, 
                    slide_type = :slide_type, 
                    added_by = :added_by, 
                    category_id = :category_id
                WHERE slide_id = :slide_id
            """)
            params = {
                "presentation_id": data.get('presentation_id', slide.presentation_id),
                "topic": data.get('topic', slide.topic),
                "industry": data.get('industry', slide.industry),
                "slide_type": slide_type if slide_type else slide.slide_type.value,
                "added_by": data.get('added_by', slide.added_by),
                "category_id": data.get('category_id', slide.category_id),
                "slide_id": slide_id
            }

            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Слайд обновлён успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при обновлении слайда: {e}")

    async_task(db_task)
    return jsonify({"msg": "Слайд обновлён успешно"}), 200

# Удаление слайда
@app.route('/slides/<int:slide_id>', methods=['DELETE'])
@role_required(['ADMIN'])
def delete_slide(slide_id):
    def db_task():
        try:
            query = text("DELETE FROM slides WHERE slide_id = :slide_id")
            params = {"slide_id": slide_id}
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Слайд удалён успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при удалении слайда: {e}")
    async_task(db_task)
    return jsonify({"msg": "Слайд удалён успешно"}), 200

# Список результатов поиска
@app.route('/search_results', methods=['GET'])
@role_required(['ADMIN', 'EDITOR'])
def get_search_results():
    search_results = SearchResult.query.all()
    result = []
    for sr in search_results:
        result.append({
            "result_id": sr.result_id,
            "user_id": sr.user_id,
            "search_query": sr.search_query,
            "result_slides": sr.result_slides,
            "search_date": sr.search_date.isoformat(),
            "duration": sr.duration
        })
    return jsonify(result), 200

# Добавление нового результата поиска
@app.route('/search_results', methods=['POST'])
@role_required(['ADMIN', 'EDITOR'])
def add_search_result():
    data = request.get_json()
    user_id = data.get('user_id')
    search_query = data.get('search_query')
    result_slides = data.get('result_slides')
    search_date = data.get('search_date')
    duration = data.get('duration')

    def db_task():
        try:
            query = text("INSERT INTO search_results (user_id, search_query, result_slides, search_date, duration) VALUES (:user_id, :search_query, :result_slides, :search_date, :duration)")
            params = {
                    "user_id": user_id,
                    "search_query": search_query,
                    "result_slides": result_slides,
                    "search_date": datetime.fromisoformat(search_date) if search_date else datetime.utcnow(),
                    "duration": duration
                }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Результат поиска добавлен успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при добавлении результата поиска: {e}")
    async_task(db_task)
    return jsonify({"msg": "Результат поиска добавлен успешно"}), 201

# Обновление результата поиска
@app.route('/search_results/<int:result_id>', methods=['PUT'])
@role_required(['ADMIN', 'EDITOR'])
def update_search_result(result_id):
    search_result = SearchResult.query.get_or_404(result_id)
    data = request.get_json()
    
    def db_task():
        try:
            query = text("""
                UPDATE search_results 
                SET user_id = :user_id, 
                    search_query = :search_query, 
                    result_slides = :result_slides, 
                    search_date = :search_date, 
                    duration = :duration
                WHERE result_id = :result_id
            """)
            params = {
                "user_id": data.get('user_id', search_result.user_id),
                "search_query": data.get('search_query', search_result.search_query),
                "result_slides": data.get('result_slides', search_result.result_slides),
                "search_date": datetime.fromisoformat(data.get('search_date')) if data.get('search_date') else search_result.search_date,
                "duration": data.get('duration', search_result.duration),
                "result_id": result_id
            }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Результат поиска обновлён успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при обновлении результата поиска: {e}")
    async_task(db_task)
    return jsonify({"msg": "Результат поиска обновлён успешно"}), 200

# Удаление результата поиска
@app.route('/search_results/<int:result_id>', methods=['DELETE'])
@role_required(['ADMIN'])
def delete_search_result(result_id):
    def db_task():
        try:
            query = text("DELETE FROM search_results WHERE result_id = :result_id")
            params = {"result_id": result_id}
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Результат поиска удалён успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при удалении результата поиска: {e}")
    async_task(db_task)
    return jsonify({"msg": "Результат поиска удалён успешно"}), 200

# Логи
@app.route('/logs', methods=['GET'])
@role_required(['ADMIN'])
def get_logs():
    logs = Log.query.all()
    result = []
    for log in logs:
        result.append({
            "log_id": log.log_id,
            "user_id": log.user_id,
            "action": log.action,
            "details": log.details,
            "log_level": log.log_level.value if log.log_level else None,
            "log_date": log.log_date.isoformat()
        })
    return jsonify(result), 200

@app.route('/logs', methods=['POST'])
@role_required(['ADMIN', 'EDITOR'])
def add_log():
    data = request.get_json()
    user_id = data.get('user_id')
    action = data.get('action')
    details = data.get('details')
    log_level = data.get('log_level')
    log_date = data.get('log_date')

    if log_level not in LogLevel.__members__:
        return jsonify({"msg": "Недопустимый уровень лога"}), 400
    
    def db_task():
        try:
            query = text("INSERT INTO logs (user_id, action, details, log_level, log_date) VALUES (:user_id, :action, :details, :log_level, :log_date)")
            params = {
                    "user_id": user_id,
                    "action": action,
                    "details": details,
                    "log_level": log_level,
                    "log_date": datetime.fromisoformat(log_date) if log_date else datetime.utcnow()
                }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Лог добавлен успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при добавлении лога: {e}")
    async_task(db_task)
    return jsonify({"msg": "Лог добавлен успешно"}), 201

@app.route('/logs/<int:log_id>', methods=['PUT'])
@role_required(['ADMIN', 'EDITOR'])
def update_log(log_id):
    log = Log.query.get_or_404(log_id)
    data = request.get_json()
    log_level = data.get('log_level')

    if log_level and log_level not in LogLevel.__members__:
        return jsonify({"msg": "Недопустимый уровень лога"}), 400
    
    def db_task():
        try:
            query = text("""
                UPDATE logs 
                SET user_id = :user_id, 
                    action = :action, 
                    details = :details, 
                    log_level = :log_level, 
                    log_date = :log_date
                WHERE log_id = :log_id
            """)
            params = {
                "user_id": data.get('user_id', log.user_id),
                "action": data.get('action', log.action),
                "details": data.get('details', log.details),
                "log_level": log_level if log_level else log.log_level.value,
                "log_date": datetime.fromisoformat(data.get('log_date')) if data.get('log_date') else log.log_date,
                "log_id": log_id
            }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Лог обновлён успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при обновлении лога: {e}")
    async_task(db_task)
    return jsonify({"msg": "Лог обновлён успешно"}), 200

@app.route('/logs/<int:log_id>', methods=['DELETE'])
@role_required(['ADMIN'])
def delete_log(log_id):
    def db_task():
        try:
            query = text("DELETE FROM logs WHERE log_id = :log_id")
            params = {"log_id": log_id}
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Лог удалён успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при удалении лога: {e}")
    async_task(db_task)
    return jsonify({"msg": "Лог удалён успешно"}), 200

# Ошибки
@app.route('/errors', methods=['GET'])
@role_required(['ADMIN'])
def get_errors():
    errors = Error.query.all()
    result = []
    for error in errors:
        result.append({
            "error_id": error.error_id,
            "user_id": error.user_id,
            "error_message": error.error_message,
            "error_level": error.error_level.value if error.error_level else None,
            "error_date": error.error_date.isoformat()
        })
    return jsonify(result), 200

@app.route('/errors', methods=['POST'])
@role_required(['ADMIN', 'EDITOR'])
def add_error():
    data = request.get_json()
    user_id = data.get('user_id')
    error_message = data.get('error_message')
    error_level = data.get('error_level')
    error_date = data.get('error_date')

    if error_level not in ErrorLevel.__members__:
        return jsonify({"msg": "Недопустимый уровень ошибки"}), 400
    
    def db_task():
        try:
            query = text("INSERT INTO errors (user_id, error_message, error_level, error_date) VALUES (:user_id, :error_message, :error_level, :error_date)")
            params = {
                    "user_id": user_id,
                    "error_message": error_message,
                    "error_level": error_level,
                    "error_date": datetime.fromisoformat(error_date) if error_date else datetime.utcnow()
                }
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Ошибка добавлена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при добавлении ошибки: {e}")
    async_task(db_task)
    return jsonify({"msg": "Ошибка добавлена успешно"}), 201

@app.route('/errors/<int:error_id>', methods=['PUT'])
@role_required(['ADMIN', 'EDITOR'])
def update_error(error_id):
    error = Error.query.get_or_404(error_id)
    data = request.get_json()
    error_level = data.get('error_level')
    if error_level and error_level not in ErrorLevel.__members__:
         return jsonify({"msg": "Недопустимый уровень ошибки"}), 400
    def db_task():
        try:
            query = text("""
            UPDATE errors
            SET user_id = :user_id,
                error_message = :error_message,
                error_level = :error_level,
                error_date = :error_date
            WHERE error_id = :error_id
            """)
            params = {
                 "user_id": data.get('user_id', error.user_id),
                 "error_message": data.get('error_message', error.error_message),
                 "error_level": error_level if error_level else error.error_level.value,
                 "error_date": datetime.fromisoformat(data.get('error_date')) if data.get('error_date') else error.error_date,
                 "error_id": error_id
            }
            db.session.execute(query,params)
            db.session.commit()
            app.logger.info("Ошибка обновлена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при обновлении ошибки: {e}")
    async_task(db_task)
    return jsonify({"msg": "Ошибка обновлена успешно"}), 200

@app.route('/errors/<int:error_id>', methods=['DELETE'])
@role_required(['ADMIN'])
def delete_error(error_id):
    def db_task():
        try:
            query = text("DELETE FROM errors WHERE error_id = :error_id")
            params = {"error_id": error_id}
            db.session.execute(query, params)
            db.session.commit()
            app.logger.info("Ошибка удалена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при удалении ошибки: {e}")
    async_task(db_task)
    return jsonify({"msg": "Ошибка удалена успешно"}), 200

# Количество слайдов по категориям
from sqlalchemy import text  # Убедитесь, что импортируете text

@app.route('/slide_count_by_category', methods=['GET'])
@role_required(['ADMIN', 'EDITOR'])
def slide_count_by_category():
    try:
        with db.engine.connect() as connection:

            result = connection.execute(text("SELECT * FROM get_slide_count_by_category();"))
            slide_counts = [{"category_name": row['category_name'], "slide_count": row['slide_count']} for row in result]

        return jsonify(slide_counts), 200
    except Exception as e:
        app.logger.error(f"Ошибка при получении данных: {e}")
        return jsonify({"msg": f"Ошибка при получении данных: {str(e)}"}), 500

# Архивация презентаций
@app.route('/archive_presentations', methods=['POST'])
@role_required(['ADMIN'])
def archive_presentations():
    data = request.get_json()
    archive_date = data.get('archive_date')

    if not archive_date:
        return jsonify({"msg": "Не указана дата архивирования"}), 400

    def db_task():
        try:
            with db.engine.connect() as connection:
                connection.execute(
                    text("CALL archive_old_presentations(:archive_date)"),
                    {"archive_date": archive_date}
                )
            app.logger.info("Архивация выполнена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при архивировании: {e}")
    async_task(db_task)
    return jsonify({"msg": "Задача на архивирование запущена"}), 202

# Восстановление презентаций
@app.route('/restore_presentations', methods=['POST'])
@role_required(['ADMIN'])
def restore_presentations():
    data = request.get_json()
    restore_date = data.get('restore_date')
    if not restore_date:
        return jsonify({"msg": "Не указана дата восстановления"}), 400
    
    def restore_task():
        try:
            with db.engine.connect() as connection:
                connection.execute(
                    text("CALL restore_presentations(:restore_date)"),
                    {"restore_date": restore_date}
                )
            app.logger.info("Восстановление выполнено успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при восстановлении: {e}")
    async_task(restore_task)
    return jsonify({"msg": "Задача на восстановление запущена"}), 202

@app.route('/create_view', methods=['POST'])
@role_required(['ADMIN'])
def create_view():
    try:
        with db.engine.begin() as connection:  # Используем db.engine.begin() для автоматического коммита
            connection.execute(text("""
            CREATE OR REPLACE VIEW public.slide_details_view AS
            SELECT
                s.slide_id,
                s.topic,
                s.industry,
                s.slide_type,
                s.added_date,
                s.added_by,
                c.category_name,
                p.name AS presentation_name
            FROM
                slides s
            LEFT JOIN
                categories c ON s.category_id = c.category_id
            LEFT JOIN
                presentations p ON s.presentation_id = p.presentation_id;
            """))
            app.logger.info("VIEW создано успешно")

            # Дополнительная проверка
            result = connection.execute(text("""
                SELECT table_schema, table_name
                FROM information_schema.views
                WHERE table_schema = 'public' AND table_name = 'slide_details_view';
            """))
            view_exists = result.rowcount > 0
            if view_exists:
                app.logger.info("Подтверждение: VIEW существует в базе данных.")
                return jsonify({"msg": "VIEW создано успешно"}), 200
            else:
                app.logger.warning("Подтверждение: VIEW НЕ найдено в базе данных.")
                return jsonify({"msg": "VIEW не был найден после создания."}), 500

    except Exception as e:
        app.logger.error(f"Ошибка при создании VIEW: {e}")
        return jsonify({"msg": f"Ошибка при создании VIEW: {str(e)}"}), 500

# Получение данных из конкретного VIEW
@app.route('/view_data/<view_name>', methods=['GET'])
@role_required(['ADMIN'])
def get_view_data(view_name):
    VALID_VIEWS = ['slide_details_view', 'test_view']  
    if view_name not in VALID_VIEWS:
        return jsonify({"msg": "Недопустимое имя представления"}), 400
    try:
        with db.engine.connect() as connection:
            query = text(f"SELECT * FROM public.{view_name};")
            result = connection.execute(query)
            columns = result.keys()
            data = [dict(zip(columns, row)) for row in result]
        return jsonify(data), 200
    except Exception as e:
        app.logger.error(f"Ошибка при получении данных из VIEW {view_name}: {e}")
        return jsonify({"msg": f"Ошибка при получении данных из VIEW: {str(e)}"}), 500

@app.route('/create_trigger', methods=['POST'])
@role_required(['ADMIN'])
def create_trigger():
    try:
        with db.engine.begin() as connection: 
            connection.execute(text("""
                ALTER TABLE presentations 
                ADD COLUMN IF NOT EXISTS updated_date TIMESTAMP WITH TIME ZONE DEFAULT NOW();
            """))
            connection.execute(text("""
                CREATE OR REPLACE FUNCTION update_presentation_timestamp()
                RETURNS TRIGGER AS $$
                BEGIN
                    UPDATE presentations
                    SET updated_date = NOW()
                    WHERE presentation_id = NEW.presentation_id;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """))
            connection.execute(text("""
                DROP TRIGGER IF EXISTS trigger_update_presentation_timestamp ON slides;
                CREATE TRIGGER trigger_update_presentation_timestamp
                AFTER INSERT OR UPDATE ON slides
                FOR EACH ROW
                EXECUTE FUNCTION update_presentation_timestamp();
            """))
        app.logger.info("TRIGGER создано успешно")
        return jsonify({"msg": "TRIGGER создано успешно"}), 200
    except Exception as e:
        app.logger.error(f"Ошибка при создании TRIGGER: {e}")
        return jsonify({"msg": f"Ошибка при создании TRIGGER: {str(e)}"}), 500

@app.route('/create_function', methods=['POST'])
@role_required(['ADMIN'])
def create_function():
    try:
        with db.engine.begin() as connection:
            connection.execute(text("""
            CREATE OR REPLACE FUNCTION get_slide_count_by_category()
            RETURNS TABLE (category_name text, slide_count bigint)
            LANGUAGE plpgsql AS $$
            BEGIN
                RETURN QUERY
                SELECT 
                    c.category_name::text, 
                    COUNT(s.slide_id)
                FROM 
                    categories c
                LEFT JOIN 
                    slides s ON c.category_id = s.category_id
                GROUP BY 
                    c.category_name;
            END;
            $$;


            """))
        app.logger.info("FUNCTION создано успешно")
        return jsonify({"msg": "FUNCTION создано успешно"}), 200
    except Exception as e:
        app.logger.error(f"Ошибка при создании FUNCTION: {e}")
        return jsonify({"msg": f"Ошибка при создании FUNCTION: {str(e)}"}), 500

@app.route('/create_stored_procedure', methods=['POST'])
@role_required(['ADMIN'])
def create_stored_procedure():
    try:
        with db.engine.begin() as connection:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS presentations_archive (
                    presentation_id INTEGER PRIMARY KEY,
                    google_slide_id VARCHAR(50) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    created_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    created_by INTEGER,
                    archived_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    FOREIGN KEY (created_by) REFERENCES users(user_id)
                );
            """))
            connection.execute(text("""
                CREATE OR REPLACE PROCEDURE archive_old_presentations(p_archive_date TIMESTAMP WITH TIME ZONE)
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    INSERT INTO presentations_archive (presentation_id, google_slide_id, name, created_date, created_by, archived_date)
                    SELECT presentation_id, google_slide_id, name, created_date, created_by, NOW()
                    FROM presentations
                    WHERE created_date < p_archive_date;

                    DELETE FROM presentations
                    WHERE created_date < p_archive_date;
                END;
                $$;
            """))
        app.logger.info("STORED PROCEDURE создано успешно")
        return jsonify({"msg": "STORED PROCEDURE создано успешно"}), 200
    except Exception as e:
        app.logger.error(f"Ошибка при создании STORED PROCEDURE: {e}")
        return jsonify({"msg": f"Ошибка при создании STORED PROCEDURE: {str(e)}"}), 500

@app.route('/check_token', methods=['GET'])
@jwt_required()
def check_token():
    current_user = get_jwt_identity()
    claims = get_jwt()
    return jsonify({
        "user": current_user,
        "role": claims.get('role', None)
    }), 200


# Экспорт в CSV
@app.route('/export_presentations_csv', methods=['GET'])
@role_required(['ADMIN', 'EDITOR'])
def export_presentations_csv():
    try:
        presentations = Presentation.query.all()
        data = []
        for pres in presentations:
            data.append({
                "presentation_id": pres.presentation_id,
                "google_slide_id": pres.google_slide_id,
                "name": pres.name,
                "created_date": pres.created_date.isoformat(),
                "created_by": pres.created_by
            })
        df = pd.DataFrame(data)
        csv = df.to_csv(index=False)
        return (csv, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=presentations.csv'
        })
    except Exception as e:
        app.logger.error(f"Ошибка при экспорте CSV: {e}")
        return jsonify({"msg": f"Ошибка при экспорте CSV: {str(e)}"}), 500

from sqlalchemy import text


# График распределения слайдов по категориям -> JPEG
@app.route('/export_slide_distribution', methods=['GET'])
@role_required(['ADMIN', 'EDITOR'])
def export_slide_distribution():
    try:
        with db.engine.connect() as connection:
            result = connection.execute(text("SELECT * FROM get_slide_count_by_category();"))
            slide_counts = [{"category_name": row[0], "slide_count": row[1]} for row in result]

        df = pd.DataFrame(slide_counts)
        plt.figure(figsize=(10,6))
        plt.bar(df['category_name'], df['slide_count'], color='skyblue')
        plt.xlabel('Категория')
        plt.ylabel('Количество Слайдов')
        plt.title('Распределение Слайдов по Категориям')
        plt.tight_layout()

        img = BytesIO()
        plt.savefig(img, format='jpeg')
        img.seek(0)

        return (img, 200, {
            'Content-Type': 'image/jpeg',
            'Content-Disposition': 'attachment; filename=slide_distribution.jpg'
        })
    except Exception as e:
        app.logger.error(f"Ошибка при генерации графика: {e}")
        return jsonify({"msg": f"Ошибка при генерации графика: {str(e)}"}), 500

@app.route('/create_backup', methods=['POST'])
@role_required(['ADMIN'])
def create_backup():
    def backup_task():
        try:
            backup_dir = 'backups'
            os.makedirs(backup_dir, exist_ok=True)
            backup_file = os.path.join(backup_dir, f"backup_{datetime.now().strftime('%Y%m%d%H%M%S')}.sql")
            db_url = DATABASE_URL
            
            db_url_parts = db_url.split("//")[1].split(":")
            db_user = db_url_parts[0]
            db_host_port = db_url_parts[1].split("@")[1] if len(db_url_parts)>1 else 'localhost:5432'
            db_host = db_host_port.split(":")[0]
            db_port = db_host_port.split(":")[1]
            db_pass = db_url_parts[1].split("@")[0]
            db_name = db_url.split("/")[-1]
            
            command = [
                 'pg_dump',
                 '-U', db_user,
                '-h', db_host,
                '-p', db_port,
                 '-F', 'c',
                 '-b',
                '-v',
                '-f', backup_file,
                db_name
            ]

            env = os.environ.copy()
            env['PGPASSWORD'] = db_pass

            subprocess.run(command, check=True, env=env)
            app.logger.info(f"Резервная копия создана: {backup_file}")
        except subprocess.CalledProcessError as e:
            app.logger.error(f"Ошибка при создании резервной копии: {e}")
        except Exception as e:
            app.logger.error(f"Неизвестная ошибка: {e}")
    async_task(backup_task)
    return jsonify({"msg": "Задача на создание резервной копии запущена"}), 202

# Восстановление базы данных
@app.route('/restore_backup', methods=['POST'])
@role_required(['ADMIN'])
def restore_backup():
    data = request.get_json()
    backup_file = data.get('backup_file')
    if not backup_file or not os.path.exists(backup_file):
            return jsonify({"msg": "Неверный путь к резервной копии"}), 400
    
    def restore_task():
        try:
            db_url = DATABASE_URL
            
             # Разбираем URL на компоненты
            db_url_parts = db_url.split("//")[1].split(":")
            db_user = db_url_parts[0]
            db_host_port = db_url_parts[1].split("@")[1] if len(db_url_parts)>1 else 'localhost:5432'
            db_host = db_host_port.split(":")[0]
            db_port = db_host_port.split(":")[1]
            db_pass = db_url_parts[1].split("@")[0]
            db_name = db_url.split("/")[-1]
            
            command = [
                 'pg_restore',
                 '-U', db_user,
                '-h', db_host,
                '-p', db_port,
                 '-d', db_name,
                '-c',
                '-v',
                backup_file
            ]

            env = os.environ.copy()
            env['PGPASSWORD'] = db_pass

            subprocess.run(command, check=True, env=env)
            app.logger.info("Восстановление выполнено успешно")
        except subprocess.CalledProcessError as e:
            app.logger.error(f"Ошибка при восстановлении базы данных: {e}")
        except Exception as e:
            app.logger.error(f"Неизвестная ошибка: {e}")
    async_task(restore_task)
    return jsonify({"msg": "Задача на восстановление запущена"}), 202

# Получение списка VIEW
@app.route('/views', methods=['GET'])
@role_required(['ADMIN'])
def get_views():
    try:
        with db.engine.connect() as connection:
            result = connection.execute(text("""
                SELECT table_schema, table_name
                FROM information_schema.views
                WHERE table_schema NOT IN ('information_schema', 'pg_catalog');
            """))
            views = [
                {"schema": row[0], "table_name": row[1]}
                for row in result.fetchall()
            ]
        if views:
            return jsonify(views), 200
        else:
            return jsonify({"msg": "Нет доступных представлений (VIEW)."}), 200
    except Exception as e:
        app.logger.error(f"Ошибка при получении представлений: {e}")
        return jsonify({"msg": f"Ошибка при получении представлений: {str(e)}"}), 500

# Получение списка триггеров
@app.route('/triggers', methods=['GET'])
@role_required(['ADMIN'])
def get_triggers():
    try:
        with db.engine.connect() as connection:
            result = connection.execute(text("""
                SELECT trigger_name, event_manipulation, event_object_table, action_statement
                FROM information_schema.triggers
                WHERE trigger_schema = 'public';
            """))
            triggers = [
                {"trigger_name": row[0], "event_manipulation": row[1],
                 "event_object_table": row[2], "action_statement": row[3]}
                for row in result.fetchall()
            ]
        return jsonify(triggers), 200
    except Exception as e:
        app.logger.error(f"Ошибка при получении триггеров: {e}")
        return jsonify({"msg": f"Ошибка при получении триггеров: {str(e)}"}), 500

# Получение списка функций
@app.route('/functions', methods=['GET'])
@role_required(['ADMIN'])
def get_functions():
    try:
        with db.engine.connect() as connection:
            result = connection.execute(text("""
                SELECT routine_name, routine_definition
                FROM information_schema.routines
                WHERE routine_schema = 'public' AND routine_type = 'FUNCTION';
            """))
            functions = [
                {"routine_name": row[0], "routine_definition": row[1]}
                for row in result.fetchall()
            ]
        return jsonify(functions), 200
    except Exception as e:
        app.logger.error(f"Ошибка при получении функций: {e}")
        return jsonify({"msg": f"Ошибка при получении функций: {str(e)}"}), 500

# Получение списка STORED PROCEDURE
@app.route('/stored_procedures', methods=['GET'])
@role_required(['ADMIN'])
def get_stored_procedures():
    try:
        with db.engine.connect() as connection:
            result = connection.execute(text("""
                SELECT routine_name, routine_definition
                FROM information_schema.routines
                WHERE routine_schema = 'public' AND routine_type = 'PROCEDURE';
            """))
            procedures = [
                {"routine_name": row[0], "routine_definition": row[1]}
                for row in result.fetchall()
            ]
        return jsonify(procedures), 200
    except Exception as e:
        app.logger.error(f"Ошибка при получении хранимых процедур: {e}")
        return jsonify({"msg": f"Ошибка при получении хранимых процедур: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
