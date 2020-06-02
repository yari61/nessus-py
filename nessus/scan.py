from .host import Host


class Scan(object):
    __slots__ = ("connector", "uuid", "id", "history", "name", "history_id", "_det")

    def __init__(self, **kwargs):
        for attr in self.__slots__:
            self.__setattr__(attr, kwargs.get(attr))
        self.history_id = self.history[-1]
        self._det = {}

    def __iter__(self):
        for history_id in self.history:
            yield self.connector.scan_details(scan_id=self.id, history_id=history_id)

    def _details(self) -> dict:
        return self.connector.scan_details(scan_id=self.id, history_id=self.history_id)

    @property
    def details(self):
        if self._det.get(self.history_id) is None:
            self._det[self.history_id] = self._details()
        return self._det[self.history_id]

    def info(self):
        return self.details.get("info")

    def host_list(self) -> list:
        hosts = self.details.get("hosts")
        return [self.host(host.get("host_id")) for host in hosts]

    def host(self, host_id: int) -> Host:
        return self.connector.host(scan_id=self.id, host_id=host_id, history_id=self.history_id)
