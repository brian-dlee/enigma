from setuptools import setup

setup(
    name='crypt',
    version='0.1.0',
    description='Utility for generating and maintaining cryptographic certs and keys',
    url='https://github.com/orionnetworksolutions/Crypt.git',
    author='Brian Lee',
    author_email='briandl92391@gmail.com',
    license='MIT',
    packages=['crypt'],
    zip_safe=True,
    test_suite='crypt.test'
)