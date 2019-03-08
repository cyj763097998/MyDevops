#/usr/bin/env python
#coding=utf-8
#edit richard  2019/3/8

from . import admin
from flask import render_template, url_for, redirect,flash,session,request
from forms import LoginForm
from functools import wraps
from app import db
from app.models import Admin


@admin.route("/")
@admin.route("/index/")
def index():
    return render_template("admin/index.html")

@admin.route("/pwd/")
def pwd():
    return render_template("admin/pwd.html")

#退出登录
@admin.route("/logout/")
def logout():
    session.pop("admin",None)
    return redirect(url_for('admin.login'))

#登录
@admin.route("/login/",methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["account"]).first()
        if not admin.check_pwd(data["pwd"]):
            flash("密码错误！")
            return redirect(url_for("admin.login"))
        session["admin"] = data["account"]
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)
