class Host(object):
    __slots__ = ("connector", "scan_id", "history_id", "id", "fqdn", "ip", "mac", "os", "plugin_entries")

    def __init__(self, **kwargs):
        for attr in self.__slots__:
            self.__setattr__(attr, kwargs.get(attr))

    def plugin_output(self, plugin_id: int):
        return self.connector.plugin_output(scan_id=self.scan_id, host_id=self.id, plugin_id=plugin_id, history_id=self.history_id)
