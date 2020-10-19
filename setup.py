import os

from setuptools import setup, find_packages


def _read_requirements(file_name):
    """
    Returns list of required modules for 'install_requires' parameter. Assumes
    requirements file contains only module lines and comments.
    """
    requirements = []
    with open(os.path.join(file_name)) as f:
        for line in f:
            if not line.startswith('#'):
                requirements.append(line)
    return requirements


INSTALL_REQUIREMENTS = _read_requirements('requirements.txt')

# README as long description
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md')) as file:
    LONG_DESCRIPTION = file.read()

setup(
    name='cose',
    version='0.9',
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.6',
    package_data={
        '': [
            'requirements.txt',
            'images/*.png',
        ],
    },
    install_requires=INSTALL_REQUIREMENTS,
    long_description=LONG_DESCRIPTION,
    keywords=['COSE', 'Internet of Things', 'CBOR', 'object security', 'EDHOC', 'OSCORE'],
    author='Timothy Claeys',
    author_email='timothy.claeys@gmail.com',
    license='BSD-3',
)
