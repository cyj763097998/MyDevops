#/usr/bin/env python
#coding=utf-8
#edit richard  2019/3/8

from flask import Blueprint
admin = Blueprint("admin",__name__)
import app.admin.views