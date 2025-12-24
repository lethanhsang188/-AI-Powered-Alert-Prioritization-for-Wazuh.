#!/usr/bin/env python
"""
Setup script for AI-Powered Alert Prioritization for Wazuh
"""

from setuptools import setup, find_packages
import os

# Read the contents of README.md
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt', 'r') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="wazuh-alert-pipeline",
    version="1.0.0",
    author="lethanhsang188",
    author_email="",
    description="AI-Powered Alert Prioritization for Wazuh - Enterprise-grade security alert processing pipeline",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh.",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    keywords="wazuh security monitoring ai alerts prioritization ids ips soc",
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "mkdocs>=1.4.0",
            "mkdocs-material>=9.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wazuh-alert-pipeline=bin.run_pipeline:main",
            "wazuh-alert-test=tools.test_active_response:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    project_urls={
        "Bug Reports": "https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh./issues",
        "Source": "https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh.",
        "Documentation": "https://lethanhsang188.github.io/-AI-Powered-Alert-Prioritization-for-Wazuh./",
    },
)
