from setuptools import setup, find_packages

setup(
    name="electrasmart",
    author="Yonatan Perry",
    author_email="yonatan.perry@gmail.com",
    version="0.8",
    description="API client for Electra Smart air conditioner",
    long_description="API client for Electra Smart air conditioner",
    url="https://github.com/yonatanp/electrasmart",
    license="MIT",
    python_requires=">=3.5.0",
    packages=find_packages(include=["electrasmart"]),
    install_requires=["requests"],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
        "Development Status :: 5 - Production/Stable",
        "Operating System :: OS Independent",
        "Topic :: Home Automation",
    ],
    entry_points={
        "console_scripts": [
            "electrasmart-auth=electrasmart.cli:auth",
            "electrasmart-list-devices=electrasmart.cli:list_devices",
            "electrasmart-gen-baseline-status=electrasmart.cli:gen_baseline_status",
            "electrasmart-send-command=electrasmart.cli:send_command",
        ]
    },
)
