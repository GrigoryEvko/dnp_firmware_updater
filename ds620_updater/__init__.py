"""
DS620A Firmware Updater for Linux

A reverse-engineered firmware updater for DNP DS620A photo printers.
"""

__version__ = "1.0.0"
__author__ = "DS620 Linux Community"
__license__ = "MIT"

from .updater import DS620Updater

__all__ = ["DS620Updater"]