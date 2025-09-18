from venv import create
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import os

from MainClass.class_auth import authLogs_Analyzer  
from MainClass.class_webLogs import WebLogScanner


## TABLES Pulled from file DB.py
from DB import User
from DB import File

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  

## DB SETUP
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_NOTIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'dev' ## this is for testing purpose, env var when prod ready


## Flask App INIT
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


ALLOWED_EXTENSIONS = {'txt', 'log'}
alerts_store = {}  # store alerts per filename

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


with app.app_context():
    db.create_all()



@app.route("/register", methods=["GET", "POST"])
def register():
    data = request.get_json()
    name = data.get("name")
    username = data.get("username")
    password = data.get('password')
    hashed = bcrypt.generate_password_hash(password).decode('utf-8')

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already registered"}), 400
    
    new_user = User(name=name, username=username, password=hashed)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "New User Succesfully Registered"}), 201


@app.route("/login", methods=["GET", "POST"])    
def login():
    data = request.get_json()
    name = data.get("name")
    username = data.get("username")
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Not able to Login"}), 401
    else:
        access_token = create_access_token(identity=username)
        return jsonify({"access token": access_token, "topics": user.topics}), 200



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/home", methods=["GET", "POST"])
@jwt_required()
def upload_file():
    if request.method == 'POST':
     
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        file_type = request.form.get('file_type', 'auth')  
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

           
            if file_type == 'web':
                analyzer = WebLogScanner(file_path)
            elif file_type == 'auth':
                analyzer = authLogs_Analyzer(file_path)
            else:
                flash('Unsupported file type')
                return redirect(request.url)

            alerts = analyzer.analyze()
            alerts_store[filename] = alerts

            flash(f'Upload successful and logs analyzed for {file_type} logs!')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid file type')
            return redirect(request.url)
    
    return render_template('upload.html')


@app.route("/alerts/<filename>", methods=["GET"])
@jwt_required()
def get_alerts(filename):
    alerts = alerts_store.get(filename)
    if alerts is None:
        return jsonify({"error": "No alerts found for this file"}), 404
    return jsonify(alerts)


@app.route("/files", methods=["GET"])
@jwt_required()
def list_files():
    """Return a list of uploaded files"""
    files = list(alerts_store.keys())
    return jsonify({"files": files})


if __name__ == '__main__':
    app.run(debug=True)
