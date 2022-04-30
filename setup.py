from setuptools import setup

setup(
    name="stealchecker",
    version="0.0.1",
    entry_points={
        "console_scripts": [
            "stealcheck = stealchecker:stealchecker.main",
        ]
    },
    packages=["stealchecker"]
)
