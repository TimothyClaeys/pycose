from setuptools import setup, find_packages

setup(
    name='pycose',
    version='0.1.1',
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.3',
    install_requires=[
        'cryptography',
        'cbor',
        'ecdsa',
    ],

    author='Timothy Claeys',
    author_email='timothy.claeys@imag.fr',
    license='BSD-3',
)
