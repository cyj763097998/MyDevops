#/usr/bin/env python
#coding=utf-8
#edit richard  2019/3/8

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,FileField,TextAreaField,SelectField
from wtforms.validators import DataRequired, ValidationError
from app.models import Admin

class LoginForm(FlaskForm):
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