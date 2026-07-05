import os

import setuptools
from setuptools import setup

_here = os.path.abspath(os.path.dirname(__file__))

# Single source of truth for the version (avoid importing the package at build).
_version = {}
with open(os.path.join(_here, "DNScanner", "_version.py")) as fh:
    exec(fh.read(), _version)

try:
    with open(os.path.join(_here, "README.md"), encoding="utf-8") as fh:
        long_description = fh.read()
except OSError:
    long_description = "Domain DNS & security review tool."

setup(
    name="DNScanner",
    version=_version["__version__"],
    description="Domain DNS & security review tool (standalone CLI + importable module)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Tiago Faustino",
    author_email="tiagfaustino@gmail.com",
    url="https://github.com/ChinadaCam/DNScanner/",
    license="GPL-3.0",
    python_requires=">=3.7",
    packages=setuptools.find_packages(exclude=("tests", "tests.*")),
    include_package_data=True,
    package_data={"DNScanner": ["Others/wordlists/*.txt"]},
    install_requires=[
        "click>=8.0",
        "requests>=2.25",
        "dnspython>=2.2",
        "ipwhois>=1.2",
        "idna>=3.0",
        "colorama>=0.4",
    ],
    extras_require={"report": ["reportlab>=3.6"]},
    entry_points={"console_scripts": ["dnscanner=DNScanner.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
