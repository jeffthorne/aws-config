import json
from datetime import datetime
import time

from suds.client import Client
import requests
from sslcontext import create_ssl_context, HTTPSTransport
from config import Config
from host_utils import HostUtils


class Manager:

    def __init__(self, username, password, tenant=None, host ='app.deepsecurity.trendmicro.com',\
                 port = "443", verify_ssl = False):
        kwargs = {}
        self._username = username
        self._password = password
        self._tenant = tenant
        self.host = host
        self.headers =  {'Content-Type': 'application/json'}

        self.port = port
        self.verify_ssl = verify_ssl
        self.config = Config(self.host, self.port)
        url = self.config.soap_url()

        if verify_ssl == False:
           sslContext = create_ssl_context(False, None, None)
           kwargs['transport'] = HTTPSTransport(sslContext)

        self.client = Client(url, **kwargs)

        if tenant:
            self.session_id = self._authenticate_tenant()
        else:
            self.session_id = self.__authenticate()

    def __authenticate(self):
        return self.client.service.authenticate(username=self._username, password=self._password)

    def _authenticate_tenant(self):
        return self.client.service.authenticateTenant(tenantName=self._tenant, username=self._username,
                                                      password=self._password)

    def get_api_version(self):
        return self.client.service.getApiVersion()

    def get_host_by_name(self, name):
        response = self.client.service.hostRetrieveByName(name, sID=self.session_id)
        return HostUtils(self.config).create_host(response)

    def host_status(self, id):
        return self.client.service.hostGetStatus(int(id), self.session_id)


    def antimalware_on(self, host_name):
        host = self.get_host_by_name(host_name)
        hs = self.host_status(host.id)
        result = hs.protectionStatusTransports[0][0].antiMalwareStatus
        ur = result.__repr__()
        print ur
        malware_off = (u"Off" in result.__repr__()) or (u"Not" in result.__repr__())
        return not malware_off

    def end_session(self):
        self.client.service.endSession(sID=self.session_id)