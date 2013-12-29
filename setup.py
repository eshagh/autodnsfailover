#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name='autodnsfailover',
    version='0.2',
    description='Automatically add/remove A records in a DNS load balancer',
    author='Jérôme Petazzoni',
    author_email='jerome.petazzoni@dotcloud.com',
    url='http://github.com/dotcloud/autodnsfailover',
    packages=['autodnsfailover'],
    install_requires=['zerigodns','boto','suds','requests']
    )
