from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import os

from Main.class_auth import authLogs_Analyzer  
from Main.class_webLogs import WebLogScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size

ALLOWED_EXTENSIONS = {'txt', 'log'}
alerts_store = {}  # store alerts per filename

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        file_type = request.form.get('file_type', 'auth')  # default to auth logs
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Select analyzer based on log type
            if file_type == 'web':
                analyzer = WebLogScanner(file_path)
            elif file_type == 'auth':
                analyzer = authLogs_Analyzer(file_path)
            else:
                flash('Unsupported file type')
                return redirect(request.url)

            # Analyze logs and store alerts
            alerts = analyzer.analyze()
            alerts_store[filename] = alerts

            flash(f'Upload successful and logs analyzed for {file_type} logs!')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid file type')
            return redirect(request.url)
    
    return render_template('upload.html')


@app.route("/alerts/<filename>", methods=["GET"])
def get_alerts(filename):
    alerts = alerts_store.get(filename)
    if alerts is None:
        return jsonify({"error": "No alerts found for this file"}), 404
    return jsonify(alerts)


@app.route("/files", methods=["GET"])
def list_files():
    """Return a list of uploaded files"""
    files = list(alerts_store.keys())
    return jsonify({"files": files})


if __name__ == '__main__':
    app.run(debug=True)
