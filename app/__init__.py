#/usr/bin/env python
#coding=utf-8
#edit richard  2019/3/8
from flask import  Flask,render_template
from flask_sqlalchemy import SQLAlchemy
import sys
import os
reload(sys)
sys.setdefaultencoding('utf-8')

app =  Flask(__name__)
app.debug = True
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/db_mydevops"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config['SECRET_KEY'] = 'b0ba9e899e254f6eaed382f19af1915e'
#app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)),"static/uploads")
db = SQLAlchemy(app)

from app.admin import admin as admin_blueprint

app.register_blueprint(admin_blueprint,url_prefix="/admin")
@app.errorhandler(404)
def page_not_found(error):
    return render_template("admin/404.html"), 404
