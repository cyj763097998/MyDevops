#/usr/bin/env python
#coding=utf-8
#edit richard  2019/3/8

from . import admin
from flask import render_template, url_for, redirect,flash,session,request
from forms import LoginForm,PwdForm,TagForm,AuthForm,RoleForm
from app.models import Admin,Tag,Auth,Role
from functools import wraps
from app import db
import datetime

#验证是否已登陆
def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if "admin" not in session:
            return redirect(url_for("admin.login",next=request.url))
        return f(*args,**kwargs)
    return decorated_function
#上下文处理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data

@admin.route("/")
@admin.route("/index/")
@admin_login_req
def index():
    return render_template("admin/index.html")

#修改密码
@admin.route("/pwd/",methods=['GET','POST'])
@admin_login_req
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session["admin"]).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功,请重新登陆！","ok")
        return redirect(url_for("admin.logout"))
    return render_template("admin/pwd.html",form=form)

#退出登录
@admin.route("/logout/")
@admin_login_req
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
            flash("密码错误！","err")
            return redirect(url_for("admin.login"))
        session["admin"] = data["account"]
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)

#添加标签
@admin.route("/tag/add/",methods=["GET","POST"])
@admin_login_req
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag_num=Tag.query.filter_by(name=data["tag_name"]).count()
        if tag_num == 1:
            flash("标签名称已经存在！","err")
            return redirect(url_for("admin.tag_add"))
        tag = Tag(
            name=data["tag_name"]
        )
        db.session.add(tag)
        db.session.commit()
        flash("添加标签成功！","ok")
        return redirect(url_for("admin.tag_add"))
    return render_template("admin/tag_add.html",form=form)

#标签列表
@admin.route("/tag/list/<int:page>/",methods=["get"])
@admin_login_req
def tag_list(page=None):
    if page is None:
        page=1
    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page,per_page=10)

    return render_template("admin/tag_list.html",page_data=page_data)

#编辑标签
@admin.route("/tag/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_num=Tag.query.filter_by(name=data["tag_name"]).count()
        if tag.name != data["tag_name"] and tag_num == 1:
            flash("标签名称已经存在！","err")
            return redirect(url_for("admin.tag_edit",id=id))
        tag.name = data["tag_name"]
        db.session.add(tag)
        db.session.commit()
        flash("修改标签成功！","ok")
        return redirect(url_for("admin.tag_edit",id=id))
    return render_template("admin/tag_edit.html",form=form,tag=tag)

#删除标签
@admin.route("/tag/del/<int:id>/",methods=["get"])
@admin_login_req
def tag_del(id=None):
    tag=Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功！","ok")
    return redirect(url_for("admin.tag_list",page=1))

#权限添加
@admin.route("/auth/add/",methods=["GET","POST"])
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data=form.data
        auth_num = Auth.query.filter_by(name=data["auth_name"]).count()
        if auth_num == 1:
            flash("权限名称已经存在！", "err")
            return redirect(url_for("admin.auth_add"))
        auth=Auth(
            name=data["auth_name"],
            url=data["auth_url"]
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功！","ok")
        return redirect(url_for("admin.auth_add"))
    return render_template("admin/auth_add.html",form=form)

#权限列表
@admin.route("/auth/list/<int:page>/",methods=["GET"])
@admin_login_req
def auth_list(page=None):
    if page is None:
        page=1
    page_data = Auth.query.order_by(
        Auth.addtime.desc()
    ).paginate(page=page,per_page=10)

    return render_template("admin/auth_list.html",page_data=page_data)

#编辑权限
@admin.route("/auth/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth_num=Auth.query.filter_by(name=data["auth_name"]).count()
        if auth.name != data["auth_name"] and auth_num == 1:
            flash("权限名称已经存在！","err")
            return redirect(url_for("admin.auth_edit",id=id))
        auth.name = data["auth_name"]
        auth.url = data["auth_url"]
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功！","ok")
        return redirect(url_for("admin.auth_edit",id=id))
    return render_template("admin/auth_edit.html",form=form,auth=auth)

#删除权限
@admin.route("/auth/del/<int:id>/",methods=["get"])
@admin_login_req
def auth_del(id=None):
    auth=Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功！","ok")
    return redirect(url_for("admin.auth_list",page=1))

#角色添加
@admin.route("/role/add/",methods=["GET","POST"])
def role_add():
    form=RoleForm()
    if form.validate_on_submit():
        data=form.data
        role = Role(
            name=data["role_name"],
            auths=','.join(map(lambda v:str(v),data["auths"])),
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
    return render_template("admin/role_add.html",form=form)

#角色列表
@admin.route("/role/list/<int:page>/",methods=["GET"])
@admin_login_req
def role_list(page=None):

    return render_template("admin/role_list.html")