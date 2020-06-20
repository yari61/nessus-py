import importlib

try:
    settings = importlib.import_module("settings")
    attributes = getattr(settings, "plugin_attributes")
except ImportError:
    from .settings import plugin_attributes as attributes


class Plugin(object):
    __slots__ = ("connector", *[attr for attr in attributes])

    def __init__(self, **kwargs):
        for attr in self.__slots__:
            self.__setattr__(attr, kwargs.get(attr))

    def __repr__(self):
        return f"<Plugin(id={self.id}, name={self.name}, family={self.family_name})>"
