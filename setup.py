from setuptools import setup

setup(
    name='libhopper',
    version='0.1',
    description='The LibHopper',
    packages=['libhopper'],
    install_requires=[
        'angr',
        'pyyaml',
    ],
)