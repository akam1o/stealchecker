from setuptools import setup

setup(
    name="stealchecker",
    version="1.0.0",
    entry_points={
        "console_scripts": [
            "stealcheck = stealchecker:stealchecker.main",
        ]
    },
    packages=["stealchecker"]
)
