from setuptools import setup
from io import open

DESCRIPTION = 'CLI and Prometheus exporter for QEMU/KVM VM CPU usage and steal time'
NAME = 'stealchecker'
AUTHOR = 'akam1o'
AUTHOR_EMAIL = '5158577+akam1o@users.noreply.github.com'
URL = 'https://github.com/akam1o/stealchecker'
LICENSE = 'MIT'
DOWNLOAD_URL = URL
VERSION = '2.1.0'
PYTHON_REQUIRES = '>=3.6'
INSTALL_REQUIRES = [
    'libvirt-python'
]
ENTRY_POINTS = {
    'console_scripts': [
        'stealchecker = stealchecker.stealchecker:main',
    ]
}
PACKAGES = [
    'stealchecker'
]
KEYWORDS = 'libvirt qemu kvm cpu steal'
CLASSIFIERS = [
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: 3.12',
    'Programming Language :: Python :: 3.13',
    'Programming Language :: Python :: 3.14',

]
with open('README.md', 'r', encoding='utf-8') as fp:
    readme = fp.read()
LONG_DESCRIPTION = readme
LONG_DESCRIPTION_CONTENT_TYPE = 'text/markdown'

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type=LONG_DESCRIPTION_CONTENT_TYPE,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    maintainer=AUTHOR,
    maintainer_email=AUTHOR_EMAIL,
    url=URL,
    download_url=URL,
    entry_points=ENTRY_POINTS,
    packages=PACKAGES,
    classifiers=CLASSIFIERS,
    license=LICENSE,
    keywords=KEYWORDS,
    python_requires=PYTHON_REQUIRES,
    install_requires=INSTALL_REQUIRES
)
