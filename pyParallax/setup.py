from setuptools import setup, find_packages

setup(
    name="pyparallax",
    version="0.2.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={"pyParallax": ["*.so"]},
    zip_safe=False,
)

