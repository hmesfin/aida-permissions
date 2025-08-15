"""
Pytest configuration for AIDA Permissions tests.
"""

import os
import sys
import django
from django.conf import settings

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure Django settings for tests
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.settings')

# Setup Django
def pytest_configure():
    if not settings.configured:
        django.setup()