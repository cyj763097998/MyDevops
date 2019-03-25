#/usr/bin/env python
#coding=utf-8
#edit richard  2019/3/8

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,FileField,TextAreaField,SelectField,SelectMultipleField
from wtforms.validators import DataRequired, ValidationError,EqualTo
from app.models import Admin,Auth,Role,Host,Sladir

class LoginForm(FlaskForm):
    """登录"""
    account = StringField(
        label="帐号",
        validators=[
            DataRequired("请输入帐号！"),
        ],
        description="帐号",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入账号！",
            "required": False
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码！"),
        ],
        description="密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入密码！",
            "required": False
        }
    )
    submit = SubmitField(
        '登录',
        render_kw={
            "class": "btn btn-primary btn-block btn-flat"
        }
    )
    def validate_account(self,field):
        data = field.data
        account_count = Admin.query.filter_by(name=data).count()
        if account_count == 0:
            raise ValidationError("帐号不存在!")

class PwdForm(FlaskForm):
    """修改密码"""
    old_pwd = PasswordField(
        label="旧密码",
        validators=[
            DataRequired("请输入旧密码！"),
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入旧密码！",
            "required": False
        }
    )
    new_pwd = PasswordField(
        label="新密码",
        validators=[
            DataRequired("请输入新密码！"),
        ],
        description="新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码！",
            "required": False
        }
    )
    submit = SubmitField(
        '修改',
        render_kw={
            "class": "btn btn-primary"
        }
    )
    def validate_old_pwd(self,field):
        pwd = field.data
        from flask import session
        admin = Admin.query.filter_by(name = session["admin"]).first()
        if not admin.check_pwd(pwd):
            raise ValidationError("密码不正确！")
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class TagForm(FlaskForm):
    """标签"""
    tag_name = StringField(
        label="标签名称",
        validators=[
            DataRequired("请输入标签名称！")
        ],
        description="标签名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入标签名称！",
            "required": False
        }
    )
    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class AuthForm(FlaskForm):
    """权限"""
    auth_name = StringField(
        label="权限名称",
        validators=[
            DataRequired("请输入权限名称！")
        ],
        description="权限名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入权限名称！",
            "required": False
        }
    )
    auth_url = StringField(
        label="权限地址",
        validators=[
            DataRequired("请输入权限地址！")
        ],
        description="权限地址",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入权限地址！",
            "required": False
        }
    )
    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class RoleForm(FlaskForm):
    """角色"""
    role_name = StringField(
        label="角色名称",
        validators=[
            DataRequired("请输入角色名称！")
        ],
        description="角色名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入角色名称！",
            "required": False
        }
    )
    auths = SelectMultipleField(
        label="操作权限",
        validators=[
            DataRequired("请选择操作权限！")
        ],
        description="权限地址",
        coerce=int,
        #choices=[(v.id,v.name) for v in Auth.query.all()],
        render_kw={
            "class": "form-control",
            "required": False
        }
    )
    # 解决下拉数据不同步
    def __init__(self, *args, **kwargs):
        super(RoleForm, self).__init__(*args, **kwargs)
        self.auths.choices = [(v.id, v.name) for v in Auth.query.all()]

    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class AdminForm(FlaskForm):
    '''管理员'''
    name = StringField(
        label="管理员名称",
        validators=[
            DataRequired("请输入管理员名称！")
        ],
        description="管理员名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入管理员名称！",
            "required": False
        }
    )
    pwd = PasswordField(
        label="管理员密码",
        validators=[
            DataRequired("请输入管理员密码！"),
        ],
        description="管理员密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入管理员密码！",
            "required": False
        }
    )
    repwd = PasswordField(
        label="管理员重复密码",
        validators=[
            DataRequired("请输入管理员重复密码！"),
            EqualTo("pwd",message="两次密码不一致！")
        ],
        description="管理员重复密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入管理员重复密码！",
            "required": False
        }
    )
    role = SelectField(
        label="所属角色",
        description="所属角色",
        coerce=int,
        #choices= [(v.id,v.name) for v in Role.query.all()],
        render_kw={
            "class": "form-control",
        }
    )
    # 解决下拉数据不同步
    def __init__(self, *args, **kwargs):
        super(AdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(v.id, v.name) for v in Role.query.all()]

    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class HostForm(FlaskForm):
    """主机"""
    host_name = StringField(
        label="主机名",
        validators=[
            DataRequired("请输入主机名！")
        ],
        description="主机名",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入主机名！",
            "required": False
        }
    )
    system = StringField(
        label="系统",
        validators=[
            DataRequired("请输入系统！")
        ],
        description="系统",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入系统！",
            "required": False
        }
    )
    outernet_ip = StringField(
        label="外网ip",
        validators=[
            DataRequired("请输入外网ip！")
        ],
        description="外网ip",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入外网ip！",
            "required": False
        }
    )
    intranet_ip = StringField(
        label="内网ip",
        validators=[
            DataRequired("请输入内网ip！")
        ],
        description="系统",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入内网ip！",
            "required": False
        }
    )
    cpu = StringField(
        label="CPU",
        validators=[
            DataRequired("请输入CPU！")
        ],
        description="CPU",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入CPU！",
            "required": False
        }
    )
    memory = StringField(
        label="内存",
        validators=[
            DataRequired("请输入内存！")
        ],
        description="内存",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入内存！",
            "required": False
        }
    )
    disk = StringField(
        label="硬盘",
        validators=[
            DataRequired("请输入硬盘！")
        ],
        description="硬盘",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入硬盘！",
            "required": False
        }
    )
    username = StringField(
        label="用户",
        validators=[
            DataRequired("请输入用户！")
        ],
        description="用户",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入用户！",
            "required": False
        }
    )
    password = StringField(
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入密码！",
            "required": False
        }
    )
    port = StringField(
        label="端口",
        validators=[
            DataRequired("请输入端口！")
        ],
        description="端口",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入端口！",
            "required": False
        }
    )
    ssh_port = StringField(
        label="ssh端口",
        validators=[
            DataRequired("请输入ssh端口！")
        ],
        description="ssh端口",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入ssh端口！",
            "required": False
        }
    )
    status = SelectField(
        label="在线状态",
        description="在线状态",
        coerce=int,
        choices= [(1,"在线"),(2,"离线") ],
        render_kw={
            "class": "form-control",
            "required": False
        }
    )
    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class SlaveForm(FlaskForm):
    """从库"""
    slave_name = StringField(
        label="从库名称",
        validators=[
            DataRequired("请输入从库名称！")
        ],
        description="从库名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入从库名称！",
            "required": False
        }
    )
    host = SelectField(
        label="主机",
        description="主机",
        coerce=int,
        render_kw={
            "class": "form-control",
        }
    )

    # 解决下拉数据不同步
    def __init__(self, *args, **kwargs):
        super(SlaveForm, self).__init__(*args, **kwargs)
        self.host.choices = [(v.id, v.outernet_ip+v.name) for v in Host.query.filter_by(status=1).all()]
    status = SelectField(
        label="当前状态",
        description="当前状态",
        coerce=int,
        choices= [(1,"在线"),(2,"离线") ],
        render_kw={
            "class": "form-control",
            "required": False
        }
    )
    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class SladirForm(FlaskForm):
    """从库目录"""
    sladir_name = StringField(
        label="目录名称",
        validators=[
            DataRequired("请输入目录名称！")
        ],
        description="目录名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入目录名称！",
            "required": False
        }
    )
    url = StringField(
        label="路径",
        validators=[
            DataRequired("请输入路径！")
        ],
        description="路径",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入路径！",
            "required": False
        }
    )
    status = SelectField(
        label="当前状态",
        description="当前状态",
        coerce=int,
        choices= [(1,"在线"),(2,"离线") ],
        render_kw={
            "class": "form-control",
            "required": False
        }
    )
    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )
class MysqlForm(FlaskForm):
    """mysql实例"""
    mysql_name = StringField(
        label="实例名称",
        validators=[
            DataRequired("请输入实例名称！")
        ],
        description="实例名称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入实例名称！",
            "required": False
        }
    )
    host_id = SelectField(
        label="主主机",
        description="主主机",
        coerce=int,
        render_kw={
            "class": "form-control",
        }
    )
    # 解决下拉数据不同步
    def __init__(self, *args, **kwargs):
        super(MysqlForm, self).__init__(*args, **kwargs)
        self.host_id.choices = [(v.id, v.name) for v in Host.query.filter_by(status=1).all()]

    master_port = StringField(
        label="实例端口",
        validators=[
            DataRequired("请输入实例端口！")
        ],
        description="实例端口",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入实例端口！",
            "required": False
        }
    )
    master_dir = StringField(
        label="主目录",
        validators=[
            DataRequired("请输入主目录！")
        ],
        description="主目录",
        #coerce=int,
        render_kw={
            "class": "form-control",
        }
    )
    # 解决下拉数据不同步
    def __init__(self, *args, **kwargs):
        super(MysqlForm, self).__init__(*args, **kwargs)
        self.master_dir.choices = [(v.id, v.name) for v in Sladir.query.all()]

    master_sock = StringField(
        label="主sock",
        validators=[
            DataRequired("请输入主sock！")
        ],
        description="主sock",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入主sock！",
            "required": False
        }
    )
    version = StringField(
        label="实例版本",
        validators=[
            DataRequired("请输入实例版本！")
        ],
        description="主sock",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入实例版本！",
            "required": False
        }
    )
    salve_id = StringField(
        label="从主机",
        validators=[
            DataRequired("请输入从主机！")
        ],
        description="从主机",
        #coerce=int,
        render_kw={
            "class": "form-control",
        }
    )
    # 解决下拉数据不同步
    def __init__(self, *args, **kwargs):
        super(MysqlForm, self).__init__(*args, **kwargs)
        self.slave_id.choices = [(v.id, v.name) for v in Slave.query.all()]

    slave_port = StringField(
        label="从端口",
        validators=[
            DataRequired("请输入从端口！")
        ],
        description="从端口",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入从端口！",
            "required": False
        }
    )
    slave_dir = StringField(
        label="从目录",
        validators=[
            DataRequired("请输入从目录！")
        ],
        description="从目录",
        #coerce=int,
        render_kw={
            "class": "form-control",
        }
    )
    # 解决下拉数据不同步
    def __init__(self, *args, **kwargs):
        super(MysqlForm, self).__init__(*args, **kwargs)
        self.slave_dir.choices = [(v.id, v.name) for v in Sladir.query.all()]

    slave_sock = StringField(
        label="从sock",
        validators=[
            DataRequired("请输入从sock！")
        ],
        description="主sock",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入从sock！",
            "required": False
        }
    )
    create = SelectField(
        label="创建",
        description="创建",
        coerce=int,
        choices= [(1,"创建"),(2,"不创建") ],
        render_kw={
            "class": "form-control",
            "required": False
        }
    )
    submit = SubmitField(
        "添加",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_edit = SubmitField(
        "编辑",
        render_kw={
            "class": "btn btn-primary"
        }
    )
    submit_back = SubmitField(
        "返回",
        render_kw={
            "class": "btn btn-success",
            "onclick" :"javascript:history.back(-1);return false;"
        }
    )