from setuptools import setup, find_packages

setup(
    name="pyparallax",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,  # include the .so file
    zip_safe=False,
)

