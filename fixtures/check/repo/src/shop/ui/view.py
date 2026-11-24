import importlib
import os

from shop.db import models
from ..db.session import open_session
from . import widgets


def load(name):
    return importlib.import_module(name)


def render():
    text = "from shop.db import models"
    return text, os.sep, models, open_session, widgets
