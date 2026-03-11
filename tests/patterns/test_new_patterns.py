import unittest
from hermes_aegis.patterns import secrets, crypto

class TestSecrets(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIsNotNone(secrets.AWS_ACCESS_KEY.search('AKIA1234567890123456'))
        self.assertIsNone(secrets.AWS_ACCESS_KEY.search('AKIA'))

    def test_github_token(self):
        self.assertIsNotNone(secrets.GITHUB_TOKEN.search('ghp_1234567890123456789012345678901234'))
        self.assertIsNone(secrets.GITHUB_TOKEN.search('ghp_123'))

    def test_jwt(self):
        self.assertIsNotNone(secrets.JWT.search('abcde.12345.67890'))
        self.assertIsNone(secrets.JWT.search('short'))

    def test_db_credentials(self):
        self.assertIsNotNone(secrets.DB_CREDENTIALS.search('password=secret123'))
        self.assertIsNone(secrets.DB_CREDENTIALS.search('password_not_secret'))

    def test_google_api_key(self):
        self.assertIsNotNone(secrets.GOOGLE_API_KEY.search('AIzaA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z'))
        self.assertIsNone(secrets.GOOGLE_API_KEY.search('AIza'))

    def test_slack_token(self):
        self.assertIsNotNone(secrets.SLACK_TOKEN.search('xoxp-09876543210abcdef098765'))
        self.assertIsNone(secrets.SLACK_TOKEN.search('xoxp-123'))

    def test_twitter_api_key(self):
        self.assertIsNotNone(secrets.TWITTER_API_KEY.search('1234567890abcdef1234567890abcdef'))
        self.assertIsNone(secrets.TWITTER_API_KEY.search('12345'))

class TestCrypto(unittest.TestCase):
    def test_ssh_private_key(self):
        self.assertIsNotNone(crypto.SSH_PRIVATE_KEY.search('-----BEGIN RSA PRIVATE KEY-----'))
        self.assertIsNone(crypto.SSH_PRIVATE_KEY.search('BEGIN RSA PRIVATE KEY'))

    def test_pem_private_key(self):
        self.assertIsNotNone(crypto.PEM_PRIVATE_KEY.search('-----BEGIN PRIVATE KEY-----'))
        self.assertIsNone(crypto.PEM_PRIVATE_KEY.search('BEGIN PRIVATE KEY'))

    def test_pem_public_key(self):
        self.assertIsNotNone(crypto.PEM_PUBLIC_KEY.search('-----BEGIN PUBLIC KEY-----'))
        self.assertIsNone(crypto.PEM_PUBLIC_KEY.search('BEGIN PUBLIC KEY'))