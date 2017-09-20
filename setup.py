from setuptools import setup

setup(
    name='enigma',
    version='0.1.1',
    description='Utility for generating and maintaining cryptographic certs and keys',
    url='https://github.com/brian-dlee/enigma.git',
    author='Brian Lee',
    author_email='briandl92391@gmail.com',
    license='MIT',
    packages=['enigma'],
    install_requires=['PyOpenSSL'],
    zip_safe=True,
    test_suite='enigma.test'
)
