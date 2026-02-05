from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


class build_py(_build_py):
    def run(self) -> None:
        repo_root = self._resolve_repo_root()
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
    def _resolve_repo_root() -> Path:
        env_root = os.environ.get("FATOORA_REPO_ROOT")
        if env_root:
            return Path(env_root)
        here = Path(__file__).resolve().parent
        cargo_ws = here / "_cargo_ws"
        if cargo_ws.is_dir():
            return cargo_ws
        # Fallback to the historical repo layout (bindings/python/..)
        try:
            return Path(__file__).resolve().parents[2]
        except IndexError:
            return here

    @staticmethod
    def _shared_lib_name() -> str:
        if os.name == "nt":
            return "fatoora_ffi.dll"
        if sys.platform == "darwin":
            return "libfatoora_ffi.dylib"
        return "libfatoora_ffi.so"


class bdist_wheel(_bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        # Force a platform wheel since we bundle a shared library.
        self.root_is_pure = False


setup(cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel})
