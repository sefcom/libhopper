from setuptools import setup

setup(
    name='LibHopper',
    version='0.1',
    description='The LibHopper',
    packages=['libhopper'],
    install_requires=[
        'angr',
    ],
)