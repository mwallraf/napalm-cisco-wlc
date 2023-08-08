"""setup.py file."""

import os

from setuptools import setup, find_packages

__author__ = 'David Barroso <dbarrosop@dravetech.com>'

def get_requirements():
    reqs_path = os.path.join(
        os.path.dirname(__file__),
        'requirements.txt'
    )
    with open(reqs_path, 'r') as f:
        reqs = [
            r.strip() for r in f
            if r.strip()
        ]
    return reqs


setup(
    name="napalm-skeleton",
    version="0.1.1",
    packages=find_packages(),
    author="David Barroso",
    author_email="dbarrosop@dravetech.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 2.7',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-skeleton",
    include_package_data=True,
    install_requires=get_requirements(),
)
