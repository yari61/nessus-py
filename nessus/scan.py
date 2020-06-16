import importlib

from .host import Host
try:
    settings = importlib.import_module("settings")
    attributes = getattr(settings, "scan_attributes")
except ImportError:
    from .settings import scan_attributes as attributes


class Scan(object):
    __slots__ = ("connector", "uuid", "id", "history", "name")

    def __init__(self, **kwargs):
        for attr in self.__slots__:
            if not attr.startswith("_"):
                self.__setattr__(attr, kwargs.get(attr))

    def __iter__(self):
        for history_id in self.history:
            yield self.historical_entry(history_id=history_id)

    def historical_entry(self, history_id: int):
        return ScanEntry(connector=self.connector, scan_id=self.id, history_id=history_id)


class ScanEntry(object):
    __slots__ = ("_connector", "_details", "scan_id", "history_id")

    def __init__(self, **kwargs):
        self.connector = kwargs.get("connector")
        for attr in self.__slots__:
            if not attr.startswith("_"):
                self.__setattr__(attr, kwargs.get(attr))

    def _historical_entry_details(self) -> dict:
        return self.connector.scan_details(scan_id=self.scan_id, history_id=self.history_id)

    @property
    def details(self):
        if self._details is None:
            self.details = self._historical_entry_details()
        return self._details

    @details.setter
    def details(self, value):
        self._details = value

    def info(self):
        return self.details.get("info")

    def host_list(self) -> list:
        hosts = self.details.get("hosts")
        return [self.host(host.get("host_id")) for host in hosts]

    def host(self, host_id: int) -> Host:
        return self.connector.host(scan_id=self.scan_id, history_id=self.history_id, host_id=host_id)

    @property
    def connector(self):
        return self._connector

    @connector.setter
    def connector(self, value):
        self._connector = value
