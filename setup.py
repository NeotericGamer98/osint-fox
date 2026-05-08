from setuptools import setup, find_packages

setup(
    name="osint-fox",
    version="1.2.0",
    description="OSINT FOX - Open Source Intelligence Tool with GUI",
    author="OSINT FOX",
    url="https://github.com/NeotericGamer98/osint-fox",
    packages=find_packages(),
    install_requires=[
        "customtkinter>=5.2.0",
        "requests>=2.31.0",
        "fpdf2>=2.7.0",
        "pillow>=10.0.0",
        "dnspython>=2.4.0",
        "phonenumbers>=8.13.0",
    ],
    extras_require={
        "full": [
            "python-whois>=0.9.0",
            "pytz>=2023.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "osint-fox=main:gui_mode",
            "osint-fox-cli=main:cli_mode",
        ],
    },
    python_requires=">=3.10",
)
