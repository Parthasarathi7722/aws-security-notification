from setuptools import setup, find_packages

setup(
    name="aws_security_notification",
    version="3.0.0",
    description="AWS Security Notifications to Slack with retry and rate limiting",
    long_description="See README.md for full documentation.",
    long_description_content_type="text/markdown",
    author="ParthaDevSec",
    license="MIT",
    url="https://github.com/Parthasarathi7722/aws-security-notification",
    package_dir={"": "src", "aws_security_notification": "aws_security_notification"},
    packages=find_packages(where="src") + ["aws_security_notification"],
    python_requires=">=3.11",
    install_requires=[
        "boto3>=1.26.0",
    ],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
