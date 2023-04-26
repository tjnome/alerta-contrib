import json
import unittest

from alerta.app import create_app, db, plugins
from alerta_graylist import GrayHandler

class GraylistBlackoutTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        test_config = {
            'TESTING': True,
            'AUTH_REQUIRED': False
        }     
        cls.app = create_app(test_config)
        cls.client = cls.app.test_client()
        plugins.plugins['graylist'] = GrayHandler()

        filter_data = {
            "environment" : "testProduction",
            "type": "graylist",
            "attributes" : {
                "pamola" : {
                    "ticket" : "PAM-31"
                },
                "host" : "host.graylisted",
                "roles": ["alert", "blackout"]
            }
        }
        response = cls.client.post('/filter', data=json.dumps(filter_data), headers={'Content-type': 'application/json'})
        
        filter_data['attributes']['host'] = 'host.graylisted.blackout'
        filter_data['attributes']['roles'] = ["blackout"]
        response = cls.client.post('/filter', data=json.dumps(filter_data), headers={'Content-type': 'application/json'})

    @classmethod
    def tearDownClass(cls):
        plugins.plugins.clear()
        db.destroy()

        
    """ self.alerta_test = {
            'event': 'graylisted',
            'resource': 'gray',
            'environment': 'Production',
            'service': ['test_service'],
            'severity': 'critical',
            'tags': []
        }
     """

    def test_sanity_filters(self):
        response = self.client.get('/filters')
        self.assertEqual(response.status_code, 200)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['total'], 2)

    def test_bypass_graylist_for_blackout(self):
        data = {
            "environment": "Production",
            "service": ["example.com"],
            "group": "Web"
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['blackout']['environment'], data['environment'])
        self.assertEqual(json_resp['blackout']['service'], data['service'])
        self.assertEqual(json_resp['blackout']['group'], data['group'])
        self.assertEqual(len(json_resp['blackout']['tags']), 0)

    def test_reject_blackout_missing_host(self):
        data = {
            "environment": "Production",
            "service": ["example.com"],
            "group": "Web",
            "tags": ['reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 403)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'error')

    def test_accept_blackout_self_hosttag(self):
        data = {
            "environment": "Production",
            "service": ["example.com"],
            "group": "Web",
            "tags": [ 'host=test.host', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['blackout']['environment'], data['environment'])
        self.assertEqual(json_resp['blackout']['service'], data['service'])
        self.assertEqual(json_resp['blackout']['group'], data['group'])
        self.assertEqual(len(json_resp['blackout']['tags']), 3)
        self.assertTrue('host=test.host' in json_resp['blackout']['tags'])
        self.assertTrue('externalid=test.externalid' in json_resp['blackout']['tags'])
        self.assertTrue('customerprefix=test.customerprefix' in json_resp['blackout']['tags'])

    def test_accept_blackout_self_host(self):
        data = {
            "environment": "Production",
            "service": ["example.com"],
            "group": "Web",
            "tags": [ 'test.host', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['blackout']['environment'], data['environment'])
        self.assertEqual(json_resp['blackout']['service'], data['service'])
        self.assertEqual(json_resp['blackout']['group'], data['group'])
        self.assertEqual(len(json_resp['blackout']['tags']), 3)
        self.assertTrue('test.host' in json_resp['blackout']['tags'])
        self.assertTrue('externalid=test.externalid' in json_resp['blackout']['tags'])
        self.assertTrue('customerprefix=test.customerprefix' in json_resp['blackout']['tags'])
    
    def test_reject_blackout_incorrect_hosttag(self):
        data = {
            "environment": "Production",
            "service": ["example.com"],
            "group": "Web",
            "tags": [ 'host=test1.host', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix' ]
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 403)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'error')

    def test_reject_blackout_incorrect_host(self):
        data = {
            "environment": "Production",
            "service": ["example.com"],
            "group": "Web",
            "tags": [ 'test1.host', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix' ]
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 403)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'error')

    def test_accept_blackout_override_customer_tags(self):
        data = {
            "environment": "Production",
            "service": ["example.com"],
            "group": "Web",
            "tags": [ 'externalid=test.notexist', 'customerprefix=test.notexist', 'host=test.host', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix' ]
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['blackout']['environment'], data['environment'])
        self.assertEqual(json_resp['blackout']['service'], data['service'])
        self.assertEqual(json_resp['blackout']['group'], data['group'])
        self.assertEqual(len(json_resp['blackout']['tags']), 3)
        self.assertTrue('externalid=test.externalid' in json_resp['blackout']['tags'])
        self.assertTrue('customerprefix=test.customerprefix' in json_resp['blackout']['tags'])


    def test_accept_blackout_filter(self):
        data = {
            "environment": "testProduction",
            "service": ["example.com"],
            "group": "Web",
            "tags": [ 'targethost=test.host', 'reporter:host=host.graylisted', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix' ]
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        print(json.loads(response.data.decode('utf-8')))
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['blackout']['environment'], data['environment'])
        self.assertEqual(json_resp['blackout']['service'], data['service'])
        self.assertEqual(json_resp['blackout']['group'], data['group'])
        self.assertEqual(len(json_resp['blackout']['tags']), 1)
        self.assertTrue('targethost=test.host' in json_resp['blackout']['tags'])

    def test_accept_blackout_filter_role(self):
        data = {
            "environment": "testProduction",
            "service": ["example.com"],
            "group": "Web",
            "tags": [ 'targethost=test.host', 'reporter:host=host.graylisted.blackout', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix' ]
        }
        response = self.client.post(
            '/blackout', data=json.dumps(data), headers={'Content-type': 'application/json'})
        print(json.loads(response.data.decode('utf-8')))
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['blackout']['environment'], data['environment'])
        self.assertEqual(json_resp['blackout']['service'], data['service'])
        self.assertEqual(json_resp['blackout']['group'], data['group'])
        self.assertEqual(len(json_resp['blackout']['tags']), 1)
        self.assertTrue('targethost=test.host' in json_resp['blackout']['tags'])