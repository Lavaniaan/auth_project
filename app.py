from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)
from datetime import timedelta
import bcrypt

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret-key-change-in-prod"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)

users_db: dict[str, dict] = {}

@app.route("/auth/register", methods=["POST"])
def register():
    username = request.headers.get("username", "").strip()
    email    = request.headers.get("email",    "").strip()
    password = request.headers.get("password", "").strip()

    if not username or not email or not password:
        return jsonify({
            "status":  "error",
            "message": "Поля username, email и password обязательны"
        }), 400

    if username in users_db:
        return jsonify({
            "status":  "error",
            "message": f"Пользователь '{username}' уже существует"
        }), 409

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    users_db[username] = {
        "email":         email,
        "password_hash": password_hash,
    }

    return jsonify({
        "status":   "success",
        "message":  "Регистрация прошла успешно",
        "username": username,
        "email":    email
    }), 200

@app.route("/auth/login", methods=["POST"])
def login():
    username = request.headers.get("username", "").strip()
    password = request.headers.get("password", "").strip()

    if not username or not password:
        return jsonify({
            "status":  "error",
            "message": "Поля username и password обязательны"
        }), 400

    user = users_db.get(username)
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"]):
        return jsonify({
            "status":  "error",
            "message": "Неверное имя пользователя или пароль"
        }), 401

    access_token  = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    return jsonify({
        "status":        "success",
        "message":       "Авторизация успешна",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "expires_in":    "5 минут (access) / 30 дней (refresh)"
    }), 200


@app.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)

    return jsonify({
        "status":       "success",
        "message":      "Access-токен обновлён",
        "access_token": new_access_token,
        "expires_in":   "5 минут"
    }), 200


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "status":  "error",
        "message": "Токен истёк. Используй /auth/refresh для обновления."
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "status":  "error",
        "message": "Недействительный токен"
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "status":  "error",
        "message": "Токен отсутствует. Передай Authorization: Bearer <token>"
    }), 401


if __name__ == "__main__":
    app.run(debug=True, port=5000)