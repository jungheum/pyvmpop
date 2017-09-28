#!/usr/bin/env python

from setuptools import setup


install_requires = [
    'pyvbox',
    'decorator',
    'python-dateutil',
    'pypiwin32',
    'dfvfs'
]


setup(
    name='pyvmpop',
    version='20170912',
    packages=["pyvmpop",
              "pyvmpop.automation",
              "pyvmpop.extracting",
              "pyvmpop.hypervisor",
              "pyvmpop.logging",
              "pyvmpop.monitoring",
              "pyvmpop.utility"],
    author='Jungheum Park',
    author_email='junghmi@gmail.com',
    url='https://github.com/jungheum/pyvmpop',
    description="A Python implementation of VMPOP (Virtual Machine POPulation System)",
    long_description=open('README.md').read(),
    license=open('LICENSE').read(),
    zip_safe=False,
    install_requires=install_requires,
    platforms=['win', 'linux'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Researchers',
        'Intended Audience :: Developers',
        'Intended Audience :: Educators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Microsoft',
        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.x',
        'Topic :: Digital Forensics',
        'Topic :: Security',
        'Topic :: Dataset Development'
    ],
)
