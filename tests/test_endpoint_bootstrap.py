"""VPN hostnames must not depend on the tunnel they are about to establish."""
import copy
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'luci-app-nava/root/usr/lib/nava'))
import manager as m
from subscription import parse_subscription_bundle,NavaError
import json


def fixture():
    nodes,_,dns,context=parse_subscription_bundle(json.dumps({'outbounds':[
        {'type':'anytls','tag':'first','server':'first.nara.test','server_port':443,'password':'fixture-only','tls':{'enabled':True}},
        {'type':'hysteria2','tag':'second','server':'second.nara.test','server_port':443,'password':'fixture-only','tls':{'enabled':True,'server_name':'explicit.nara.test'}}]}),include_context=True)
    return {'nodes':nodes,'dns':dns,'dns_context':context}


def answer(host,port,**kwargs):
    return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('203.0.113.8',port))]


class EndpointBootstrapTests(unittest.TestCase):
    def test_default_resolves_before_stop_preserves_tls_names_cache_and_no_dns_config(self):
        cache=fixture();original=copy.deepcopy(cache);events=[]
        with tempfile.TemporaryDirectory() as directory, patch.object(m,'DATA',Path(directory)),patch.object(m,'RUN',Path(directory)),patch.object(m,'running',return_value=True),patch.object(m,'check_config'),patch.object(m,'wait_running'),patch.object(m,'wait_dns'),patch.object(m,'apply_autostart'),patch.object(m,'probe',return_value=True):
            def lookup(host,port,**kwargs):
                self.assertNotIn('stop',events);events.append('resolve');return answer(host,port,**kwargs)
            def service(action):
                events.append(action)
                if action=='start':
                    runtime=m.read_json(m.DATA/'config.json')
                    self.assertNotIn('dns',runtime)
                    self.assertNotIn('default_domain_resolver',runtime['route'])
                    self.assertFalse(any(i.get('tag')=='nava-dns-in' for i in runtime['inbounds']))
                    actual=[o for o in runtime['outbounds'] if o.get('server')]
                    self.assertEqual([o['server'] for o in actual],['203.0.113.8','203.0.113.8'])
                    self.assertEqual([o['tls']['server_name'] for o in actual],['first.nara.test','explicit.nara.test'])
            with patch.object(m.socket,'getaddrinfo',side_effect=lookup),patch.object(m,'service',side_effect=service):
                m.activate(m.DEFAULTS,cache)
        self.assertEqual(events,['resolve','resolve','stop','start'])
        self.assertEqual(cache,original)

    def test_selected_hostname_resolution_failure_preserves_active_connection(self):
        cache=fixture();config={**m.DEFAULTS,'selected':cache['nodes'][0]['id']}
        with tempfile.TemporaryDirectory() as directory,patch.object(m,'DATA',Path(directory)),patch.object(m,'RUN',Path(directory)),patch.object(m,'running',return_value=True),patch.object(m,'service') as service,patch.object(m.socket,'getaddrinfo',side_effect=socket.gaierror('unavailable')):
            old={'previous':'working'};m.atomic_json(m.DATA/'config.json',old)
            with self.assertRaisesRegex(NavaError,'before reconnecting'):
                m.activate(config,cache)
            service.assert_not_called()
            self.assertEqual(m.read_json(m.DATA/'config.json'),old)

    def test_automatic_can_skip_unresolvable_node_without_changing_library(self):
        cache=fixture();original=copy.deepcopy(cache)
        generated=m.connection_config(m.DEFAULTS,cache)
        def lookup(host,port,**kwargs):
            if host.startswith('first.'):raise socket.gaierror('not found')
            return answer(host,port,**kwargs)
        with patch.object(m.socket,'getaddrinfo',side_effect=lookup):
            m.prepare_proxy_endpoints(generated)
        first,second=[node['id'] for node in cache['nodes']]
        self.assertNotIn(first,[outbound['tag'] for outbound in generated['outbounds']])
        for outbound in generated['outbounds']:
            if outbound['type'] in ('urltest','selector'):
                self.assertNotIn(first,outbound['outbounds']);self.assertIn(second,outbound['outbounds'])
        self.assertEqual(cache,original)

    def test_manual_server_does_not_depend_on_other_servers_dns(self):
        cache=fixture();selected=cache['nodes'][1]['id']
        generated=m.connection_config({**m.DEFAULTS,'selected':selected},cache)
        with patch.object(m.socket,'getaddrinfo',side_effect=answer) as lookup:
            m.prepare_proxy_endpoints(generated,selected,False)
        lookup.assert_called_once()
        self.assertEqual(lookup.call_args.args[0],'second.nara.test')
        self.assertEqual(lookup.call_args.kwargs['family'],socket.AF_INET)

    def test_ip_servers_do_not_trigger_dns_lookup_and_transport_host_is_preserved(self):
        cache=fixture();generated=m.connection_config(m.DEFAULTS,cache)
        nodes=[o for o in generated['outbounds'] if o.get('server')]
        nodes[0]['server']='203.0.113.8'
        nodes[1]['transport']={'type':'ws','path':'/fixture','headers':{'host':'explicit-host.nara.test'}}
        with patch.object(m.socket,'getaddrinfo',side_effect=answer) as lookup:
            m.prepare_proxy_endpoints(generated)
        self.assertEqual(lookup.call_count,1)
        self.assertEqual(nodes[1]['transport']['headers'],{'host':'explicit-host.nara.test'})

    def test_implicit_websocket_host_remains_hostname_after_pinning(self):
        cache=fixture();generated=m.connection_config(m.DEFAULTS,cache)
        native=next(o for o in generated['outbounds'] if o.get('server')=='first.nara.test')
        native['transport']={'type':'ws','path':'/fixture'}
        with patch.object(m.socket,'getaddrinfo',side_effect=answer):m.prepare_proxy_endpoints(generated)
        self.assertEqual(native['transport']['headers']['Host'],'first.nara.test')
