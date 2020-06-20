from setuptools import setup

setup(
      name='NessusConnector',
      version='1.0',
      description='Connector to nessus vulnerability scanner',
      author='Yaroslav Borysiuk',
      author_email='yaroslav.borysiuk@lifecell.com.ua',
      packages=['nessus'],
      install_requires=["requests"]
)
