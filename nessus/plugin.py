class Plugin(object):
    __slots__ = ("connector", "name", "family_name", "id", "plugin_type", "plugin_publication_date",
                 "exploitability_ease", "exploit_available", "in_the_news",
                 "cvss3_vector", "cvss3_base_score", "cve",
                 "solution", "description", "synopsis")

    def __init__(self, **kwargs):
        for attr in self.__slots__:
            self.__setattr__(attr, kwargs.get(attr))

    def output(self, scan_id: int, host_id: int, history_id: int = None):
        return self.connector.plugin_output(scan_id=scan_id, host_id=host_id, plugin_id=self.id, history_id=history_id)
