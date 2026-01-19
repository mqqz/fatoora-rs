from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class build_py(_build_py):
    def run(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        target_dir = repo_root / "target" / "release"

        subprocess.check_call(
            ["cargo", "build", "-p", "fatoora-ffi", "--release"], cwd=repo_root
        )

        lib_name = self._shared_lib_name()
        lib_path = target_dir / lib_name
        if not lib_path.exists():
            raise FileNotFoundError(f"Missing FFI library: {lib_path}")

        package_dir = Path(self.build_lib) / "fatoora"
        package_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(lib_path, package_dir / lib_name)

        super().run()

    @staticmethod
    def _shared_lib_name() -> str:
        if os.name == "nt":
            return "fatoora_ffi.dll"
        if sys.platform == "darwin":
            return "libfatoora_ffi.dylib"
        return "libfatoora_ffi.so"


setup(cmdclass={"build_py": build_py})
