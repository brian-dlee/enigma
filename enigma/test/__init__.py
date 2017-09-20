import datetime
import os
import shutil
import unittest

import enigma


class TestSSL(unittest.TestCase):
    def setUp(self):
        self.__ssl_cert = enigma.SSLCertGenerator()
        self.__tmp_paths = []

    def tearDown(self):
        if len(self.__tmp_paths) > 0:
            for path in self.__tmp_paths:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)

    def __load(self):
        install_directory = os.path.join(os.getcwd(), 'tmp')

        self.__tmp_paths.append(install_directory)

        self.__ssl_cert.generate()
        self.__ssl_cert.install(install_directory)

        new_ssl_cert = enigma.SSLCertGenerator()
        new_ssl_cert.load(
            os.path.join(install_directory, 'cert.pem'),
            os.path.join(install_directory, 'privkey.pem'))

        return new_ssl_cert

    def __get_valid_time_length(self, ssl_cert=None):
        fmt = '%Y%m%d%H%M%SZ'

        ssl_cert = ssl_cert or self.__ssl_cert

        expire_date = datetime.datetime.strptime(ssl_cert.cert.get_notAfter(), fmt)
        start_date = datetime.datetime.strptime(ssl_cert.cert.get_notBefore(), fmt)

        return int((expire_date - start_date).total_seconds())

    def test_1_init(self):
        assert isinstance(self.__ssl_cert, enigma.SSLCertGenerator)

    def test_2_set_subject_data_short(self):
        self.__ssl_cert.set_subject_data('C', 'US')
        assert self.__ssl_cert.cert.get_subject().C == 'US'

    def test_2_set_subject_data_long(self):
        self.__ssl_cert.set_subject_data('countryName', 'US')
        assert self.__ssl_cert.cert.get_subject().C == 'US'

    def test_2_set_subject_data_san_single(self):
        alternate_name = 'URI:altname'
        self.__ssl_cert.set_subject_data('san', alternate_name)
        assert str(self.__ssl_cert.cert.get_extension(0)) == alternate_name

    def test_2_set_subject_data_san_multiple(self):
        altername_names = ['URI:altname', 'URI:altname2']
        self.__ssl_cert.set_subject_data('san', altername_names)
        assert str(self.__ssl_cert.cert.get_extension(0)) == ', '.join(altername_names)

    def test_2_set_subject_data_invalid(self):
        with self.assertRaises(KeyError):
            self.__ssl_cert.set_subject_data('X', 'abc')

    def test_3_generate(self):
        self.__ssl_cert.generate()

        try:
            self.__ssl_cert.cert.get_signature_algorithm() and self.__ssl_cert.key.check()
        except Exception as e:
            self.fail(e)

        self.assertTrue(True)

    def test_3_generate_with_subject(self):
        self.__ssl_cert.generate(subject={'C': 'US'})
        assert self.__ssl_cert.cert.get_subject().C == 'US'

    def test_3_generate_with_validFor(self):
        days = 10

        self.__ssl_cert.generate(valid_for=days)

        correct_valid_for_in_seconds = days * 24 * 60 * 60
        real_valid_for_in_seconds = self.__get_valid_time_length()

        assert correct_valid_for_in_seconds == real_valid_for_in_seconds

        self.assertTrue(True)

    def test_4_load(self):
        self.__load()
        self.assertTrue(True)

    def test_5_renew(self):
        ssl_cert = self.__load()
        ssl_cert.renew()

        try:
            ssl_cert.cert.get_signature_algorithm() and ssl_cert.key.check()
        except Exception as e:
            self.fail(e)

        assert ssl_cert.cert.get_serial_number() > 1000

    def test_5_renew_with_validFor(self):
        days = 10

        ssl_cert = self.__load()
        ssl_cert.renew(valid_for=days)

        correct_valid_for_in_seconds = days * 24 * 60 * 60
        real_valid_for_in_seconds = self.__get_valid_time_length(ssl_cert)

        assert correct_valid_for_in_seconds == real_valid_for_in_seconds

    def test_6_install(self):
        self.__ssl_cert.generate()
        self.__ssl_cert.install(os.getcwd())

        self.__tmp_paths.append(os.path.join(os.getcwd(), 'cert.pem'))
        self.__tmp_paths.append(os.path.join(os.getcwd(), 'privkey.pem'))

        assert os.path.exists(self.__tmp_paths[0]) and os.path.exists(self.__tmp_paths[1])

    def test_6_install_custom_dir_and_names(self):
        output_dir = os.path.join(os.getcwd(), 'tmp')
        cert_name = 'custom_cert_name.pem'
        key_name = 'custom_key_name.pem'

        self.__tmp_paths.append(output_dir)

        cert_path = os.path.join(output_dir, cert_name)
        key_path = os.path.join(output_dir, key_name)

        self.__ssl_cert.install(output_dir, cert_file=cert_name, key_file=key_name)

        assert os.path.exists(cert_path) and os.path.exists(key_path)


if __name__ == '__main__':
    unittest.main()
