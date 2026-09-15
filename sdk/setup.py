"""
Setup file for Malware Detector SDK
"""

from setuptools import setup, find_packages

setup(
    name="malware-detector-sdk",
    version="2.1.0",
    author="Mayur Nhavalde",
    author_email="mayur.nhavalde@gmail.com",
    description="Python SDK for Malware Detector API",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mayurOG/FileGuard",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.32.3",
    ],
    entry_points={
        "console_scripts": [
            "malware-detector=malware_sdk:MalwareDetectorCLI.main",
        ],
    },
)
