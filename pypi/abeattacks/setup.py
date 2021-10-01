#!/usr/bin/env python

from setuptools import setup

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='abeattacks',
    version='1.0.1',    
    description='This library implements several attacks against broken ABE schemes',
    url='https://github.com/adelapie/practical_attacks_abe',
    author='Antonio de la Piedra, Marloes Venema',
    author_email='antonio@delapiedra.org',
    license='GPL 3',
    packages=['abeattacks'],
    long_description=long_description,
    long_description_content_type='text/markdown',

    classifiers=[
        'Operating System :: POSIX :: Linux',        
        'Programming Language :: Python :: 3.7',
    ],
)

