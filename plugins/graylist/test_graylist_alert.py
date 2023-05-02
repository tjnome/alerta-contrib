import json
import unittest
from copy import deepcopy

from alerta.app import create_app, db, plugins
from alerta_graylist import GrayHandler
from flask import Flask
from flask.testing import FlaskClient


class GraylistAlertTestCase(unittest.TestCase):
    app: Flask
    client: FlaskClient

    def setUp(self) -> None:
        test_config = {
            'TESTING': True,
            'AUTH_REQUIRED': False
        }
        self.app = create_app(test_config)
        self.client = self.app.test_client()
        plugins.plugins['graylist'] = GrayHandler()

        filter_data = {
            'environment': 'Development',
            'type': 'graylist',
            'attributes': {
                'pamola': {
                    'ticket': 'PAM-31'
                },
                'host': 'host.graylisted',
                'roles': ['alert', 'blackout']
            }
        }
        # Add corrupted filter
        corrupted_filter_data = deepcopy(filter_data)
        corrupted_filter_data['attributes'] = {}
        self.client.post('/filter', data=json.dumps(
            corrupted_filter_data), headers={'Content-type': 'application/json'})

        # Original
        self.client.post(
            '/filter', data=json.dumps(filter_data), headers={'Content-type': 'application/json'})

        # Modified
        filter_data['attributes']['host'] = 'host.graylisted.alert'
        filter_data['attributes']['roles'] = ['alert']
        self.client.post(
            '/filter', data=json.dumps(filter_data), headers={'Content-type': 'application/json'})

    def tearDown(self) -> None:
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

    def test_sanity_filters(self) -> None:
        response = self.client.get('/filters')
        self.assertEqual(response.status_code, 200)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['total'], 3)

    def test_bypass_graylist_for_alert(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Production',
            'service': ['example.com'],
            'group': 'Web',
            'tags': ['plain_tag', 'plain='],
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 2)

    def test_alert_add_host(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Production',
            'service': ['example.com'],
            'group': 'Web',
            'tags': ['externalid=test.externalid', 'customerprefix=test.customerprefix', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 3)
        self.assertTrue('host=test.host' in json_resp['alert']['tags'])
        self.assertTrue(
            'customerprefix=test.customerprefix' in json_resp['alert']['tags'])
        self.assertTrue(
            'externalid=test.externalid' in json_resp['alert']['tags'])

    def test_alert_add_incorrect_host(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Production',
            'service': ['example.com'],
            'group': 'Web',
            'tags': ['host=test.host.notself', 'externalid=test.externalid', 'customerprefix=test.customerprefix', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 3)
        self.assertTrue('host=test.host' in json_resp['alert']['tags'])
        self.assertTrue(
            'customerprefix=test.customerprefix' in json_resp['alert']['tags'])
        self.assertTrue(
            'externalid=test.externalid' in json_resp['alert']['tags'])

    def test_alert_add_customer(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Production',
            'service': ['example.com'],
            'group': 'Web',
            'tags': ['host=test.host', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 3)
        self.assertTrue('host=test.host' in json_resp['alert']['tags'])
        self.assertTrue(
            'customerprefix=test.customerprefix' in json_resp['alert']['tags'])
        self.assertTrue(
            'externalid=test.externalid' in json_resp['alert']['tags'])

    def test_alert_targethost_self(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Production',
            'service': ['example.com'],
            'group': 'Web',
            'tags': ['targethost=test.host', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 4)
        self.assertTrue('targethost=test.host' in json_resp['alert']['tags'])
        self.assertTrue('host=test.host' in json_resp['alert']['tags'])
        self.assertTrue(
            'customerprefix=test.customerprefix' in json_resp['alert']['tags'])
        self.assertTrue(
            'externalid=test.externalid' in json_resp['alert']['tags'])

    def test_alert_targethost_notself(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Production',
            'service': ['example.com'],
            'group': 'Web',
            'tags': ['targethost=test.host', 'host=test.host.notself', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 3)
        self.assertTrue('host=test.host' in json_resp['alert']['tags'])
        self.assertTrue(
            'customerprefix=test.customerprefix' in json_resp['alert']['tags'])
        self.assertTrue(
            'externalid=test.externalid' in json_resp['alert']['tags'])

    def test_alert_targethost_notself_customer(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Production',
            'service': ['example.com'],
            'group': 'Web',
            'tags': ['targethost=test.host', 'host=test.host.notself', 'externalid=test.externalid.notself', 'customerprefix=test.customerprefix.notself', 'reporter:host=test.host', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 3)
        self.assertTrue('host=test.host' in json_resp['alert']['tags'])
        self.assertTrue(
            'customerprefix=test.customerprefix' in json_resp['alert']['tags'])
        self.assertTrue(
            'externalid=test.externalid' in json_resp['alert']['tags'])

    def test_alert_targethost_notself_graylisted(self) -> None:
        data = {
            'resource': 'resource',
            'event': 'event',
            'environment': 'Development',
            'service': ['notself.com'],
            'group': 'Web',
            'tags': ['targethost=test.host', 'host=test.host.notself', 'externalid=test.externalid.notself', 'customerprefix=test.customerprefix.notself',
                     'reporter:host=host.graylisted', 'reporter:externalid=test.externalid', 'reporter:customerprefix=test.customerprefix']
        }
        response = self.client.post(
            '/alert', data=json.dumps(data), headers={'Content-type': 'application/json'})
        self.assertEqual(response.status_code, 201)
        json_resp = json.loads(response.data.decode('utf-8'))
        self.assertEqual(json_resp['status'], 'ok')
        self.assertEqual(json_resp['alert']['resource'], data['resource'])
        self.assertEqual(json_resp['alert']['event'], data['event'])
        self.assertEqual(json_resp['alert']
                         ['environment'], data['environment'])
        self.assertEqual(json_resp['alert']['service'], data['service'])
        self.assertEqual(json_resp['alert']['group'], data['group'])
        self.assertEqual(len(json_resp['alert']['tags']), 4)
        self.assertTrue('targethost=test.host' in json_resp['alert']['tags'])
        self.assertTrue('host=test.host.notself' in json_resp['alert']['tags'])
        self.assertTrue(
            'customerprefix=test.customerprefix.notself' in json_resp['alert']['tags'])
        self.assertTrue(
            'externalid=test.externalid.notself' in json_resp['alert']['tags'])
