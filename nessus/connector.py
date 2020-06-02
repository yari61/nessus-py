import re

from requests import Session, Response, packages, RequestException

from .scan import Scan
from .plugin import Plugin
from .host import Host
from .settings import ssl_verify, port

packages.urllib3.disable_warnings()


def plugin_output_beautify(func):
    def wrapper(self, scan_id: int, host_id: int, plugin_id: int, history_id: int = None):
        output = list()
        exp = re.compile("^(?P<port>[0-9]+) / (?P<protocol>[a-z]+) / (?P<service>[a-z0-9]+)$")
        entries = func(self, scan_id=scan_id, host_id=host_id, plugin_id=plugin_id, history_id=history_id)
        for entry in entries:
            for service in entry.get("ports").keys():
                service = exp.match(service)
                kwargs = {"port": None if service is None else service.group("port"),
                          "protocol": None if service is None else service.group("protocol"),
                          "service": None if service is None else service.group("service"),
                          "output": entry.get("plugin_output"),
                          "severity": entry.get("severity")}
                output.append(kwargs)
        return output
    return wrapper


class Connector(object):
    __slots__ = ("_url", "_port", "_access_key", "_secret_key", "_verify", "_ssl_cert", "_ssl_key")

    def __init__(self, **kwargs):
        self.url = kwargs.get("url")
        self.port = kwargs.get("port")
        self.access_key = kwargs.get("access_key")
        self.secret_key = kwargs.get("secret_key")
        self.verify = kwargs.get("verify")
        self._ssl_cert = kwargs.get("ssl_cert")
        self._ssl_key = kwargs.get("ssl_key")

    def scanners(self) -> dict:
        method = "GET"
        uri = "/scanners"
        return self.connect(method=method, uri=uri).json()

    def scans(self, lmd: int = None, folder_id: int = None, owner=None, name=None) -> list:
        scans_list = self._scans_list(lmd=lmd, folder_id=folder_id)
        scans_to_return = list()
        for scan in scans_list:
            cor_owner = owner is None or scan.get("owner") == owner
            cor_name = name is None or scan.get("name") == name
            cor_lmd = lmd is None or scan.get("last_modification_date") >= lmd
            cor_folder = folder_id is None or scan.get("folder_id") == folder_id
            if cor_owner and cor_name and cor_lmd and cor_folder:
                scans_to_return.append(scan)
        return scans_to_return

    def _scans_list(self, lmd: int = None, folder_id: int = None) -> list:
        method = "GET"
        uri = "/scans"
        data = dict()
        if lmd is not None:
            data["last_modification_date"] = lmd
        if folder_id is not None:
            data["folder_id"] = folder_id
        return self.connect(method=method, uri=uri, data=data).json().get("scans")

    def folders(self) -> dict:
        method = "GET"
        uri = "/folders"
        return self.connect(method=method, uri=uri).json()

    def scan_details(self, scan_id: int, history_id: int = None):
        method = "GET"
        uri = f"/scans/{scan_id}"
        data = {"history_id": history_id} if history_id is not None else None
        return self.connect(method=method, uri=uri, data=data).json()

    def scan(self, scan_id: int) -> Scan:
        kwargs = self.scan_details(scan_id=scan_id)
        info = kwargs.pop("info")
        hosts = kwargs.pop("hosts")
        history = kwargs.pop("history")
        vulnerabilities = kwargs.pop("vulnerabilities")
        remediations = kwargs.pop("remediations")
        notes = kwargs.pop("notes")
        filters = kwargs.pop("filters")
        compliance = kwargs.pop("compliance")
        comphosts = kwargs.pop("comphosts")
        kwargs["name"] = info.get("name")
        kwargs["id"] = info.get("object_id")
        kwargs["uuid"] = info.get("uuid")
        kwargs["history"] = [entry.get("history_id") for entry in history]
        return Scan(connector=self, **kwargs)

    def host_details(self, scan_id: int, host_id: int, history_id: int = None):
        method = "GET"
        uri = f"/scans/{scan_id}/hosts/{host_id}"
        data = {"history_id": history_id} if history_id is not None else None
        return self.connect(method=method, uri=uri, data=data).json()

    def host(self, scan_id: int, host_id: int, history_id: int = None) -> Host:
        kwargs = self.host_details(scan_id=scan_id, host_id=host_id, history_id=history_id)
        info = kwargs.pop("info")
        vulnerabilities = kwargs.pop("vulnerabilities")
        compliance = kwargs.pop("compliance")
        kwargs["scan_id"] = scan_id
        kwargs["history_id"] = history_id
        kwargs["id"] = host_id
        kwargs["fqdn"] = info.get("host-fqdn")
        kwargs["ip"] = info.get("host-ip")
        kwargs["mac"] = info.get("mac-address")
        kwargs["os"] = info.get("operating-system")
        kwargs["plugin_entries"] = [entry.get("plugin_id") for entry in vulnerabilities]
        return Host(connector=self, **kwargs)

    def plugin(self, plugin_id: int) -> Plugin:
        method = "GET"
        uri = f"/plugins/plugin/{plugin_id}"
        kwargs = self.connect(method=method, uri=uri).json()
        attributes = kwargs.pop("attributes")
        for attr in attributes:
            name = attr.get("attribute_name")
            value = attr.get("attribute_value")
            kwargs[name] = value
        return Plugin(connector=self, **kwargs)

    @plugin_output_beautify
    def plugin_output(self, scan_id: int, host_id: int, plugin_id: int, history_id: int = None) -> dict:
        method = "GET"
        uri = f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"
        data = {"history_id": history_id} if history_id is not None else None
        return self.connect(method=method, uri=uri, data=data).json().get("outputs")

    def connect(self, method: str, uri: str, headers: dict = None, data: dict = None, verify: bool = None) -> Response:
        verify = verify if verify is not None else ssl_verify
        headers = headers if headers is not None else self.default_headers
        url = f"https://{self.url}:{self.port}{uri}"
        cert = (self.ssl_cert, self.ssl_key) if self.ssl_cert is not None and self.ssl_key is not None else None
        session: Session = Session()
        response = session.request(method=method, url=url, headers=headers, data=data, verify=verify, cert=cert)
        if response.status_code != 200:
            raise RequestException(response.reason)
        return response

    @property
    def default_headers(self):
        return {"Content-Type": "application/json",
                "X-ApiKeys": f"accessKey={self.access_key} ; secretKey={self.secret_key}"}

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value: str):
        if value is not None:
            self._url = value
        else:
            raise AttributeError("You must specify url")

    @property
    def access_key(self):
        return self._access_key

    @access_key.setter
    def access_key(self, value: str):
        if value is not None:
            self._access_key = value
        else:
            raise AttributeError("You must specify access key")

    @property
    def secret_key(self):
        return self._secret_key

    @secret_key.setter
    def secret_key(self, value: str):
        if value is not None:
            self._secret_key = value
        else:
            raise AttributeError("You must specify secret key")

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value: int):
        if value is not None:
            self._port = value
        else:
            self._port = port

    @property
    def verify(self):
        return self._verify

    @verify.setter
    def verify(self, value: bool = None):
        self._verify = value if value is not None else ssl_verify

    @property
    def ssl_cert(self):
        return self._ssl_cert

    @ssl_cert.setter
    def ssl_cert(self, value: str = None):
        self._ssl_cert = value

    @property
    def ssl_key(self):
        return self._ssl_key

    @ssl_key.setter
    def ssl_key(self, value: str = None):
        self._ssl_key = value
