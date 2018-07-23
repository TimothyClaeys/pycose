from setuptools import setup

setup(
    name='pycose',
    version='0.1',
    py_modules=['pycose'],
    python_requires='>=3.3',
    install_requires=[
        'cryptography',
        'cbor',
    ],

	author='Timothy Claeys',
	author_email='timothy.claeys@imag.fr',
	license='BSD-3',
)
