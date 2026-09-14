import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from ui_portal import install_ui

class PortalTests(unittest.TestCase):
    def setUp(self):
        from pathlib import Path
        self.app=FastAPI()
        install_ui(self.app,Path(__file__).resolve().parent.parent / 'ui' / 'index.html','https://identity.example')
        self.client=TestClient(self.app)

    def test_root_is_interface(self):
        r=self.client.get('/')
        self.assertEqual(r.status_code,200)
        self.assertIn('text/html',r.headers['content-type'])
        self.assertEqual(r.headers['cache-control'],'no-store')

    def test_login_forwards_to_fixed_authority(self):
        with patch('ui_portal.open_request',return_value=io.BytesIO(b'{"access_token":"iam_example","identity":{}}')) as opened:
            r=self.client.post('/ui/session',json={'email':'test@example.com','password':'example-password'})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['access_token'],'iam_example')
        self.assertEqual(opened.call_args.args[0].full_url,'https://identity.example/v1/auth/login')

    def test_bad_credentials_remain_rejected(self):
        with patch('ui_portal.open_request',side_effect=HTTPError('url',401,'denied',{},None)):
            r=self.client.post('/ui/session',json={'email':'test@example.com','password':'wrong'})
        self.assertEqual(r.status_code,401)

    def test_authority_failure_is_visible(self):
        with patch('ui_portal.open_request',side_effect=URLError('offline')):
            r=self.client.post('/ui/session',json={'email':'test@example.com','password':'example-password'})
        self.assertEqual(r.status_code,503)

    def test_redirect_is_not_followed(self):
        with patch('ui_portal.open_request',side_effect=HTTPError('url',302,'redirect',{},None)):
            r=self.client.post('/ui/session',json={'email':'test@example.com','password':'example-password'})
        self.assertEqual(r.status_code,503)

    def test_existing_api_routes_are_unchanged(self):
        @self.app.get('/health')
        def health():return {'status':'ok'}
        self.assertEqual(self.client.get('/health').json(),{'status':'ok'})
