import json
from datetime import datetime
import time

from suds.client import Client
import requests
from sslcontext import create_ssl_context, HTTPSTransport
from config import Config
from host_utils import HostUtils
from host import AWSHost


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
        host_details = self.client.factory.create("EnumHostDetailLevel")
        response = self.client.service.hostRetrieveByName(name, sID=self.session_id)
        return HostUtils(self.config).create_host(response)

    def host_status(self, id):
        return self.client.service.hostGetStatus(int(id), self.session_id)


    def _host_detail_retreive(self):
        host_filter_type = self.client.factory.create("EnumHostFilterType")
        host_details = self.client.factory.create("EnumHostDetailLevel")
        host_filter_transport = self.client.factory.create("HostFilterTransport")
        host_filter_transport['type'] = host_filter_type['ALL_HOSTS']
        data = {
                    'sID': self.session_id,
                    'hostFilter': host_filter_transport,
                    'hostDetailLevel': host_details['HIGH']
                }
        response = self.client.service.hostDetailRetrieve(sID=self.session_id, hostDetailLevel=host_details['HIGH'], hostFilter=host_filter_transport)
        return response



    def process_aws_hosts(self):
        hosts = []
        host_detail_transport = self._host_detail_retreive()
        for host in host_detail_transport:
            if host.cloudObjectType == "AMAZON_VM":
                instance_id = host.cloudObjectInstanceId
                id = host.ID
                ip = host.lastIPUsed
                name = host.name
                aws_host =  AWSHost(id, ip, name, instance_id)
                hosts.append(aws_host)

        return hosts


    def does_aws_host_have_malware_turned_on(self, instance_id):
        hosts = self.process_aws_hosts()
        host = [x for x in hosts if x.name == instance_id or x.ip == instance_id or x.instance_id == instance_id]

        if host:
            return self.antimalware_on(host[0])
        else:
            return None


    def antimalware_on(self, host):
        hs = self.host_status(host.id)
        result = hs.protectionStatusTransports[0][0].antiMalwareStatus
        ur = result.__repr__()
        host.malware_protection_status = ur
        malware_off = (u"Off" in result.__repr__()) or (u"Not" in result.__repr__())
        host.malware_protection_on = not malware_off
        return host

    def end_session(self):
        self.client.service.endSession(sID=self.session_id)