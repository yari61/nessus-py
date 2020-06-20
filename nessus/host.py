import importlib

try:
    settings = importlib.import_module("settings")
    attributes = getattr(settings, "host_attributes")
except ImportError:
    from .settings import host_attributes as attributes


class Host(object):
    __slots__ = ("connector", *[attr for attr in attributes])

    def __init__(self, **kwargs):
        for attr in self.__slots__:
            self.__setattr__(attr, kwargs.get(attr))

    def __repr__(self):
        return f"<Host(fqdn={getattr(self, 'fqdn', None)}, ip={getattr(self, 'ip', None)})>"

    def details(self):
        return self.connector.host_details(scan_id=self.scan_id, history_id=self.history_id, host_id=self.id)

    def plugin_list(self):
        return [self.connector.plugin(plugin_id=plugin.get("plugin_id")) for plugin in self.details().get("vulnerabilities")]

    def plugin_output(self, plugin_id: int):
        return self.connector.plugin_output(scan_id=self.scan_id, host_id=self.id, plugin_id=plugin_id, history_id=self.history_id)
