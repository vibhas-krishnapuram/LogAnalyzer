from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import os


from class_auth import authLogs_Analyzer  

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

ALLOWED_EXTENSIONS = {'txt', 'log'}
alerts_store = []  




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def upload_file():
    global alerts_store
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)


            analyzer = authLogs_Analyzer(file_path)
            alerts_store = analyzer.analyze()

            flash('Upload successful and logs analyzed!')
            return redirect(url_for('upload_file'))
        else:
            flash('Invalid file type')
            return redirect(request.url)
    
    return render_template('upload.html')


@app.route("/alerts", methods=["GET"])
def get_alerts():
    return jsonify(alerts_store)


if __name__ == '__main__':
    app.run(debug=True)
