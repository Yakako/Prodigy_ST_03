# conftest.py
# Shared pytest configuration for the login test suite.
# Hooks for HTML report generation and test metadata.

import pytest
from datetime import datetime


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "positive: marks positive/happy-path tests")
    config.addinivalue_line("markers", "negative: marks negative/edge-case tests")
    config.addinivalue_line("markers", "ui: marks UI/UX assertion tests")
    config.addinivalue_line("markers", "security: marks security-related tests")


def pytest_html_report_title(report):
    report.title = "Prodigy Infotech — Login Automation Test Report"


def pytest_html_env(report, environment):
    """Inject metadata into HTML report environment table."""
    environment["Project"] = "Task-03 Automated Login Testing"
    environment["Organization"] = "Prodigy Infotech"
    environment["Target URL"] = "https://www.saucedemo.com"
    environment["Browser"] = "Google Chrome (Headless)"
    environment["Framework"] = "Pytest + Selenium WebDriver"
    environment["Date"] = datetime.now().strftime("%B %d, %Y %H:%M")
