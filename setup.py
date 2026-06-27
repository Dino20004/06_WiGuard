from setuptools import setup, find_packages

setup(
    name="wiguard",
    version="1.0.0",
    author="Dino20004",
    author_email="dino20004@example.com",
    description="AI-Powered WiFi Evil Twin Detection CLI Tool",
    long_description=open("README.md", "r", encoding="utf-8").read() if open("README.md", "r", encoding="utf-8") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/Dino20004/WiGuard",
    packages=find_packages(),
    py_modules=["main", "wiguard"],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.12",
    install_requires=[
        "rich>=13.0.0",
        "tabulate>=0.9.0",
        "requests>=2.31.0",
        "psutil>=5.9.0",
    ],
    entry_points={
        "console_scripts": [
            "wiguard=main:main",
        ],
    },
)
