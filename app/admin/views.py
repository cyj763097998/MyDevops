#/usr/bin/env python
#coding=utf-8
#edit richard  2019/3/8

from . import admin
from flask import render_template, url_for, redirect,flash,session,request,abort,jsonify
from forms import LoginForm,PwdForm,TagForm,AuthForm,RoleForm,AdminForm,HostForm,SlaveForm,SladirForm,MysqlForm
from app.models import Admin,Tag,Auth,Role,Host,Slave,Sladir,Mysql
from functools import wraps
from app import db
import datetime
import requests
import json

#验证是否已登陆
def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if "admin" not in session:
            return redirect(url_for("admin.login",next=request.url))
        return f(*args,**kwargs)
    return decorated_function
#权限控制装饰器
def admin_auth(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session["admin_id"]
        ).first()
        auths = admin.roles.auths
        auths = list(map(lambda v: int(v), auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val == v.id]
        rule = request.url_rule
        if str(rule) not in urls and admin.is_super ==0:
            abort(403)
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
        session["admin_id"] = admin.id
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)

#添加标签
@admin.route("/tag/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
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
        #return jsonify(code=200, status=0, message='ok', data={})
    return render_template("admin/tag_add.html",form=form)

#标签列表
@admin.route("/tag/list/<int:page>/",methods=["get"])
@admin_login_req
@admin_auth
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
@admin_auth
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
@admin_auth
def tag_del(id=None):
    tag=Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功！","ok")
    return redirect(url_for("admin.tag_list",page=1))

#权限添加
@admin.route("/auth/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data=form.data
        auth_num = Auth.query.filter_by(name=data["auth_name"]).count()
        if auth_num == 1:
            flash("权限名称已经存在！", "err")
            return redirect(url_for("admin.auth_add"))
        auth_url_num = Auth.query.filter_by(url=data["auth_url"]).count()
        if auth_url_num == 1:
            flash("权限地址已经存在！", "err")
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
@admin_auth
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
@admin_auth
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth_num=Auth.query.filter_by(name=data["auth_name"]).count()
        if auth.name != data["auth_name"] and auth_num == 1:
            flash("权限名称已经存在！","err")
            return redirect(url_for("admin.auth_edit",id=id))
        auth_url_num = Auth.query.filter_by(url=data["auth_url"]).count()
        if auth_url_num == 1:
            flash("权限地址已经存在！", "err")
            return redirect(url_for("admin.auth_add",id=id))
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
@admin_auth
def auth_del(id=None):
    auth=Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功！","ok")
    return redirect(url_for("admin.auth_list",page=1))

#角色添加
@admin.route("/role/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def role_add():
    form=RoleForm()
    if form.validate_on_submit():
        data=form.data
        role_num=Role.query.filter_by(name=data["role_name"]).count()
        if role_num == 1:
            flash("角色名称已经存在！","err")
            return redirect(url_for("admin.role_add"))
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
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/role_list.html",page_data=page_data)

#编辑角色
@admin.route("/role/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def role_edit(id=None):
    form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method == "GET":
        auths = role.auths
        form.auths.data = list(map(lambda v:int(v),auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        role_num=Role.query.filter_by(name=data["role_name"]).count()
        if role.name != data["role_name"] and role_num == 1:
            flash("角色名称已经存在！","err")
            return redirect(url_for("admin.role_edit",id=id))
        role.name = data["role_name"]
        role.auths = ','.join(map(lambda v:str(v),data["auths"])),
        db.session.add(role)
        db.session.commit()
        flash("修改角色成功！","ok")
        return redirect(url_for("admin.role_edit",id=id))
    return render_template("admin/role_edit.html",form=form,role=role)

#删除角色
@admin.route("/role/del/<int:id>/",methods=["get"])
@admin_login_req
@admin_auth
def role_del(id=None):
    role=Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash("删除角色成功！","ok")
    return redirect(url_for("admin.role_list",page=1))

#管理员添加
@admin.route("/admin/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def admin_add():
    form=AdminForm()
    if form.validate_on_submit():
        data=form.data
        admin_num = Admin.query.filter_by(name=data['name']).count()
        if admin_num == 1:
            flash("管理员名称已经存在！","err")
            return redirect(url_for("admin.admin_add"))
        from werkzeug.security import generate_password_hash
        admin = Admin(
            name=data['name'],
            pwd=generate_password_hash(data['pwd']),
            role_id=data['role']
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功！", "ok")
    return render_template("admin/admin_add.html",form=form)

#管理员列表
@admin.route("/admin/list/<int:page>/",methods=["GET"])
@admin_login_req
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(
        Role
        ).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/admin_list.html",page_data=page_data)
#编辑管理员
@admin.route("/admin/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def admin_edit(id=None):
    form = AdminForm()
    admin = Admin.query.get_or_404(id)
    if request.method == "GET":
        form.pwd.data = admin.pwd
        form.role.data = admin.role_id
    if form.validate_on_submit():
        data = form.data
        admin_num=Admin.query.filter_by(name=data["name"]).count()
        if admin.name != data["name"] and admin_num == 1:
            flash("管理员名称已经存在！","err")
            return redirect(url_for("admin.admin_edit",id=id))
        from werkzeug.security import generate_password_hash
        admin.name = data["name"]
        admin.pwd = generate_password_hash(data["pwd"])
        admin.role_id = data["role"]
        db.session.add(admin)
        db.session.commit()
        flash("修改管理员成功！","ok")
        return redirect(url_for("admin.admin_edit",id=id))
    return render_template("admin/admin_edit.html",form=form,admin=admin)

#删除管理员
@admin.route("/admin/del/<int:id>/",methods=["get"])
@admin_login_req
@admin_auth
def admin_del(id=None):
    admin=Admin.query.filter_by(id=id).first_or_404()
    db.session.delete(admin)
    db.session.commit()
    flash("删除管理员成功！","ok")
    return redirect(url_for("admin.admin_list",page=1))

#添加主机
@admin.route("/host/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def host_add():
    form = HostForm()
    if form.validate_on_submit():
        data = form.data
        name_count = Host.query.filter_by(name=data["host_name"]).count()
        if name_count == 1:
            flash("主机名已经存在！","err")
            return redirect(url_for("admin.host_add"))
        outernetip_num = Host.query.filter_by(outernet_ip=data["outernet_ip"]).count()
        if outernetip_num == 1:
            flash("外网IP已经存在！", "err")
            return redirect(url_for("admin.host_add"))
        host = Host(
            name = data["host_name"],
            system = data["system"],
            outernet_ip = data["outernet_ip"],
            intranet_ip = data["intranet_ip"],
            cpu = data["cpu"],
            memory = data["memory"],
            disk = data["disk"],
            username = data["username"],
            password = data["password"],
            port = data["port"],
            ssh_port = data["ssh_port"],
            status = data["status"],
        )
        db.session.add(host)
        db.session.commit()
        flash("添加主机成功","ok")
        return redirect(url_for("admin.host_add"))
    return render_template("admin/host_add.html",form=form)

#主机列表
@admin.route("/host/list/<int:page>/",methods=["get"])
@admin_login_req
@admin_auth
def host_list(page=None):
    if page is None:
        page=1
    page_data = Host.query.order_by(
        Host.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/host_list.html",page_data=page_data)
#编辑主机
@admin.route("/host/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def host_edit(id=None):
    form = HostForm()
    host = Host.query.get_or_404(id)
    if request.method == "GET":
        form.status.data = host.status
    if form.validate_on_submit():
        data = form.data
        host_num=Host.query.filter_by(name=data["host_name"]).count()
        if host.name != data["host_name"] and host_num == 1:
            flash("主机名已经存在！","err")
            return redirect(url_for("admin.host_edit",id=id))
        outernetip_num =Host.query.filter_by(outernet_ip=data["outernet_ip"]).count()
        if host.outernet_ip != data["outernet_ip"] and outernetip_num == 1:
            flash("外网IP已经存在！","err")
            return redirect(url_for("admin.host_edit",id=id))
        host.name = data["host_name"]
        host.system = data["system"]
        host.outernet_ip = data["outernet_ip"]
        host.intranet_ip = data["intranet_ip"]
        host.cpu = data["cpu"]
        host.memory = data["memory"]
        host.disk = data["disk"]
        host.username = data["username"]
        host.password = data["password"]
        host.port = data["port"]
        host.ssh_port = data["ssh_port"]
        host.status = data["status"]
        db.session.add(host)
        db.session.commit()
        flash("修改主机成功！","ok")
        return redirect(url_for("admin.host_edit",id=id))
    return render_template("admin/host_edit.html",form=form,host=host)

#删除主机
@admin.route("/host/del/<int:id>/",methods=["get"])
@admin_login_req
@admin_auth
def host_del(id=None):
    host=Host.query.filter_by(id=id).first_or_404()
    db.session.delete(host)
    db.session.commit()
    flash("删除主机成功！","ok")
    return redirect(url_for("admin.host_list",page=1))

#从库列表
@admin.route("/slave/list/<int:page>/",methods=["get"])
@admin_login_req
@admin_auth
def slave_list(page=None):
    if page is None:
        page=1
    page_data = Slave.query.order_by(
        Slave.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/slave_list.html",page_data=page_data)

#添加从库
@admin.route("/slave/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def slave_add():
    form = SlaveForm()
    if form.validate_on_submit():
        data = form.data
        slave_num = Slave.query.filter_by(name=data["slave_name"]).count()
        if slave_num == 1:
            flash("从库已经存在！", "err")
            return redirect(url_for("admin.slave_add"))
        slave = Slave(
            name = data["slave_name"],
            host_id = data["host"],
            status = data["status"],
        )
        db.session.add(slave)
        db.session.commit()
        flash("添加从库成功","ok")
        return redirect(url_for("admin.slave_add"))
    return render_template("admin/slave_add.html",form=form)

#编辑从库
@admin.route("/slave/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def slave_edit(id=None):
    form = SlaveForm()
    slave = Slave.query.get_or_404(id)
    if request.method == "GET":
        form.status.data = slave.status
        form.host.data = slave.host_id
    if form.validate_on_submit():
        data = form.data
        slave_num=Slave.query.filter_by(name=data["slave_name"]).count()
        if slave.name != data["slave_name"] and slave_num == 1:
            flash("从库名已经存在！","err")
            return redirect(url_for("admin.slave_edit",id=id))
        slave.name = data["slave_name"],
        slave.host_id = data["host"],
        slave.status = data["status"],
        db.session.add(slave)
        db.session.commit()
        flash("修改从库成功！","ok")
        return redirect(url_for("admin.slave_edit",id=id))
    return render_template("admin/slave_edit.html",form=form,slave=slave)

#删除从库
@admin.route("/slave/del/<int:id>/",methods=["get"])
@admin_login_req
@admin_auth
def slave_del(id=None):
    slave=Slave.query.filter_by(id=id).first_or_404()
    db.session.delete(slave)
    db.session.commit()
    flash("删除从库成功！","ok")
    return redirect(url_for("admin.slave_list",page=1))

#目录列表
@admin.route("/sladir/list/<int:page>/",methods=["get"])
@admin_login_req
@admin_auth
def sladir_list(page=None):
    if page is None:
        page=1
    page_data = Sladir.query.order_by(
        Sladir.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/sladir_list.html",page_data=page_data)

#添加目录
@admin.route("/sladir/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def sladir_add():
    form = SladirForm()
    if form.validate_on_submit():
        data = form.data
        sladir_num = Sladir.query.filter_by(name=data["sladir_name"]).count()
        if sladir_num == 1:
            flash("目录名已经存在！", "err")
            return redirect(url_for("admin.sladir_add"))
        url_num = Sladir.query.filter_by(url=data["url"]).count()
        if url_num == 1:
            flash("路径已经存在！", "err")
            return redirect(url_for("admin.sladir_add"))
        sladir = Sladir(
            name = data["sladir_name"],
            url = data["url"],
            status = data["status"],
        )
        db.session.add(sladir)
        db.session.commit()
        flash("添加目录成功","ok")
        return redirect(url_for("admin.sladir_add"))
    return render_template("admin/sladir_add.html",form=form)

#编辑目录
@admin.route("/sladir/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def sladir_edit(id=None):
    form = SladirForm()
    sladir = Sladir.query.get_or_404(id)
    if request.method == "GET":
        form.status.data = sladir.status
    if form.validate_on_submit():
        data = form.data
        sladir_num=Sladir.query.filter_by(name=data["sladir_name"]).count()
        if sladir.name != data["sladir_name"] and sladir_num == 1:
            flash("目录名已经存在！","err")
            return redirect(url_for("admin.sladir_edit",id=id))
        url_num = Sladir.query.filter_by(url=data["url"]).count()
        if sladir.name != data["sladir_name"] and url_num == 1:
            flash("路径已经存在！", "err")
            return redirect(url_for("admin.sladir_edit",id=id))
        sladir.name = data["sladir_name"],
        sladir.url = data["url"],
        sladir.status = data["status"],
        db.session.add(sladir)
        db.session.commit()
        flash("修改目录成功！","ok")
        return redirect(url_for("admin.sladir_edit",id=id))
    return render_template("admin/sladir_edit.html",form=form,sladir=sladir)

#删除目录
@admin.route("/sladir/del/<int:id>/",methods=["get"])
@admin_login_req
@admin_auth
def sladir_del(id=None):
    sladir=Sladir.query.filter_by(id=id).first_or_404()
    db.session.delete(sladir)
    db.session.commit()
    flash("删除目录成功！","ok")
    return redirect(url_for("admin.sladir_list",page=1))


#实例列表
@admin.route("/mysql/list/<int:page>/",methods=["get"])
@admin_login_req
@admin_auth
def mysql_list(page=None):
    if page is None:
        page=1
    page_data = Mysql.query.order_by(
        Mysql.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/mysql_list.html",page_data=page_data)

#添加实例
@admin.route("/mysql/add/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def mysql_add():
    form = MysqlForm()
    if form.validate_on_submit():
        data = form.data
        mysql_num = Mysql.query.filter_by(name=data["mysql_name"]).count()
        #if mysql_num == 1:
        #    flash("实例名已经存在！", "err")
        #    return redirect(url_for("admin.mysql_add"))

        mysql = Mysql(
            name = data["mysql_name"],
            host_id = data["host_id"],
            master_port = data["master_port"],
            master_dir = data["master_dir"],
            master_sock = data["master_sock"],
            version = data["version"],
            slave_id = data["slave_id"],
            slave_port = data["slave_port"],
            slave_dir = data["slave_dir"],
            slave_sock = data["slave_sock"],
        )

        if data["create"] == 1:
            master_id = Host.query.filter_by(id=data["host_id"]).first()
            slave_id = Slave.query.filter_by(id=data["slave_id"]).first()
            master_dir = Sladir.query.filter_by(id=data["master_dir"]).first()
            slave_dir = Sladir.query.filter_by(id=data["slave_dir"]).first()
            info_data = {
                "name": data["mysql_name"],
                "master_id": master_id.outernet_ip,
                "master_port": data["master_port"],
                "master_dir": master_dir.url,
                "master_sock": data["master_sock"],
                "version": data["version"],
                "slave_id": slave_id.host.outernet_ip,
                "slave_port": data["slave_port"],
                "slave_dir": slave_dir.url,
                "slave_sock": data["slave_sock"],
            }

            #r = requests.post("http://" + str(master_id.outernet_ip) + ":9999/api/create_masterhost", data=info_data)
            response_json = requests.post("http://127.0.0.1:9999/api/create_masterhost", data=info_data).text
            res = json.loads(response_json)
            if res["code"] == 200:
                #flash(res["message"], "ok")
                db.session.add(mysql)
                db.session.commit()
                flash("添加实例成功", "ok")
                return redirect(url_for("admin.mysql_add"))
            else:
                flash(res["message"], "err")
                return redirect(url_for("admin.mysql_add"))
        else:
            db.session.add(mysql)
            db.session.commit()
            flash("添加实例成功", "ok")
            return redirect(url_for("admin.mysql_add"))
    return render_template("admin/mysql_add.html",form=form)
'''
#编辑目录
@admin.route("/mysql/edit/<int:id>/",methods=["GET","POST"])
@admin_login_req
@admin_auth
def mysql_edit(id=None):
    form = MysqlForm()
    mysql = Mysql.query.get_or_404(id)
    if request.method == "GET":
        form.status.data = sladir.status
    if form.validate_on_submit():
        data = form.data
        sladir_num=Sladir.query.filter_by(name=data["sladir_name"]).count()
        if sladir.name != data["sladir_name"] and sladir_num == 1:
            flash("目录名已经存在！","err")
            return redirect(url_for("admin.sladir_edit",id=id))
        url_num = Sladir.query.filter_by(url=data["url"]).count()
        if sladir.name != data["sladir_name"] and url_num == 1:
            flash("路径已经存在！", "err")
            return redirect(url_for("admin.sladir_edit",id=id))
        sladir.name = data["sladir_name"],
        sladir.url = data["url"],
        sladir.status = data["status"],
        db.session.add(sladir)
        db.session.commit()
        flash("修改目录成功！","ok")
        return redirect(url_for("admin.sladir_edit",id=id))
    return render_template("admin/sladir_edit.html",form=form,sladir=sladir)

#删除目录
@admin.route("/sladir/del/<int:id>/",methods=["get"])
@admin_login_req
@admin_auth
def sladir_del(id=None):
    sladir=Sladir.query.filter_by(id=id).first_or_404()
    db.session.delete(sladir)
    db.session.commit()
    flash("删除目录成功！","ok")
    return redirect(url_for("admin.sladir_list",page=1))
'''

