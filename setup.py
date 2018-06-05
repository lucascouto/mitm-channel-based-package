import setuptools

with open("README.md" ,"r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="mitm_channel_based",
    version="0.0.3",
    author="Lucas Woody",
    author_email="loc.unb@gmail.com",
    description="This package enable to use the computer as a Rogue AP in a MitM Channel-Based attack",
    long_description = long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lucascouto/mitm-channel-based-package",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)