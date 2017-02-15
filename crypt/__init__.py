import datetime
import os
import sys

class SSLCertGenerator(object):
    @staticmethod
    def get_cert_valid_timespan(cert):
        fmt = '%Y%m%d%H%M%SZ'

        expire_date = datetime.datetime.strptime(cert.get_notAfter(), fmt)
        start_date = datetime.datetime.strptime(cert.get_notBefore(), fmt)

        return int((expire_date - start_date).total_seconds())

    def __init__(self):
        self.cert = OpenSSL.crypto.X509()
        self.key = OpenSSL.crypto.PKey()

    def __sign(self):
        if self.key.type() == 0:
            self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        try:
            self.cert.get_signature_algorithm()
        except ValueError:
            self.cert.set_pubkey(self.key)
            self.cert.sign(self.key, 'sha256')

    def generate(self, subject=None, valid_for=365):
        subject = subject or {}

        for key in subject:
            self.set_subject_data(key, subject[key])

        if self.cert.get_serial_number() == 0:
            self.cert.set_serial_number(1000)

        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(valid_for * 24 * 60 * 60)

        self.cert.set_issuer(self.cert.get_subject())

        self.__sign()

    def install(self, install_dir, cert_file='cert.pem', key_file='priv_key.pem'):
        if not os.path.exists(install_dir):
            os.makedirs(install_dir)

        self.generate()

        open(os.path.join(install_dir, cert_file), "wt").write(
            OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, self.cert))

        open(os.path.join(install_dir, key_file), "wt").write(
            OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, self.key))

    def load(self, cert_file, key_file):
        with open(cert_file) as cert_fp:
            self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_fp.read())

        with open(key_file) as key_fp:
            self.key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_fp.read())

    def renew(self, valid_for=None):
        self.cert.set_serial_number(self.cert.get_serial_number() + 1)
        self.cert.gmtime_adj_notBefore(0)

        if valid_for is not None:
            self.cert.gmtime_adj_notAfter(valid_for * 24 * 60 * 60)
        else:
            self.cert.gmtime_adj_notAfter(SSL.get_cert_valid_timespan(self.cert))

        self.__sign()

    def set_subject_data(self, key, value):
        subject = self.cert.get_subject()

        if key.lower() in ('subjectAltName', 'san'):
            san = ', '.join(value) if isinstance(value, (list, tuple)) else value
            self.cert.add_extensions([
                OpenSSL.crypto.X509Extension(
                    "subjectAltName", False, san
                )])
            return

        if hasattr(subject, key):
            setattr(subject, key, value)
        else:
            raise KeyError('Cert Subject key {0} doesn\'t exist'.format(key))
