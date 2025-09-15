from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite://users.sqlite3"


db = SQLAlchemy(app)

## pair with mongo later



@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"




if __name__ == '__main__':
        app.run(debug=True)