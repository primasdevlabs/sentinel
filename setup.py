from setuptools import setup, find_packages

setup(
    name="sentinel-security-sdk",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "pyyaml>=5.4.1",
    ],
    entry_points={
        "pytest11": [
            "sentinel = sentinel_sdk.pytest_plugin",
        ],
    },
)
