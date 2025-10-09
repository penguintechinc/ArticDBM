#!/usr/bin/env python3
"""
ArticDBM Manager - py4web Application Runner
Enterprise Database Proxy Management Portal
"""

import os
import sys

# Run py4web with the apps folder
os.system('py4web run --host 0.0.0.0 --port 8000 apps --watch off')