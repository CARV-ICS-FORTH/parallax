# pyParallax

Python binding interface for Parallax.

## Features

- Python interface to Parallax core functions
- Easy-to-install via pip in a virtual environment

## Installation

```bash
# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install pyParallax
cd build
pip install .

```

## Usage

After installing `pyParallax` in your virtual environment, you can import and use it in your Python code.

```bash
import pyParallax as py_par

py_par.format("/example.db", 10)

handle = py_par.open("/example.db", "example_db_name", py_par.opts.PAR_CREATE_DB)

py_par.close(handle)
