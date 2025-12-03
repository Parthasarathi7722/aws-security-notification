from setuptools import setup, find_packages

setup(
    name="aws_security_notification",
    version="2.1.0",
    description="AWS Security Notifications to Slack with retry and rate limiting",
    long_description="See README.md for full documentation.",
    long_description_content_type="text/markdown",
    author="ParthaDevSec",
    license="MIT",
    url="https://github.com/Parthasarathi7722/aws-security-notification",
    packages=find_packages(include=["aws_security_notification", "aws_security_notification.*"]),
    py_modules=["SecOps_notification"],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
        "boto3>=1.26.0",
    ],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
