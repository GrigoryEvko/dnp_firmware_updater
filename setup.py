#!/usr/bin/env python3
"""
Setup script for DS620A Firmware Updater
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="ds620-firmware-updater",
    version="1.0.0",
    author="DS620 Linux Community",
    description="Firmware updater for DNP DS620A photo printers on Linux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GrigoryEvko/dnp_firmware_updater",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Hardware :: Hardware Drivers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.6",
    install_requires=[
        "pyusb>=1.2.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov",
            "black",
            "flake8",
            "mypy",
        ],
    },
    entry_points={
        "console_scripts": [
            "ds620-updater=ds620_updater.updater:main",
            "ds620-firmware-updater=ds620_updater.updater:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ds620_updater": ["../firmware/*"],
    },
    zip_safe=False,
)