import os
import subprocess

from distutils.core import setup, Extension

from pybind11.setup_helpers import (
    Pybind11Extension,
    build_ext,
    ParallelCompile,
    naive_recompile,
)

# ParallelCompile("NPY_NUM_BUILD_JOBS").install()
ParallelCompile("NPY_NUM_BUILD_JOBS", needs_recompile=naive_recompile).install()

INCLUDE_DIRS = subprocess.getoutput("pybind11-config --include")

# os.environ ["CFLAGS"] = ''

PKG_NAME = "rekorder_test"
EXT_NAMES = ["rekorder"]
__version__ = "0.0.1"

ext_modules = [
    Pybind11Extension(
        EXT_NAMES[0],
        include_dirs=[INCLUDE_DIRS],
        sources=["lz4.c", "wrap.cpp"],
        define_macros=[("EXTENSION_NAME", EXT_NAMES[0])],
        extra_compile_args=["-O3", "-std=c++17"],
    ),
]

setup(
    name=PKG_NAME,
    version="0.0.1",
    author="John Doe",
    description="Example",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
)
