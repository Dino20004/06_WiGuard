from setuptools import setup, find_packages

setup(
    name="wiguard",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "rich", "colorama", "tabulate", "mac-vendor-lookup", "psutil", "requests"
    ],
    entry_points={
        'console_scripts': [
            'wiguard = wiguard.main:main',
        ],
    },
    python_requires=">=3.10",
)
