from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.build_py import build_py as _build_py
from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


class build_py(_build_py):
    def run(self) -> None:
        repo_root = self._resolve_repo_root()
        target_dir = repo_root / "target" / "release"

        subprocess.check_call(
            ["cargo", "build", "-p", "fatoora-ffi", "--release", "--locked"], cwd=repo_root
        )

        lib_name = self._shared_lib_name()
        lib_path = target_dir / lib_name
        if not lib_path.exists():
            raise FileNotFoundError(f"Missing FFI library: {lib_path}")

        package_dir = Path(self.build_lib) / "fatoora"
        # Removed modules must not survive into a wheel from an earlier build.
        if package_dir.exists():
            shutil.rmtree(package_dir)
        package_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(lib_path, package_dir / lib_name)
        native_library = (package_dir / lib_name).resolve()
        if sys.platform == "darwin":
            subprocess.check_call(["install_name_tool", "-id", f"@rpath/{lib_name}", str(native_library)])

        native_source = Path(__file__).resolve().parent / "native"
        native_build = Path(self.build_lib).resolve().parent / "native"
        subprocess.check_call([
            "cmake", "-S", str(native_source), "-B", str(native_build),
            "-DCMAKE_BUILD_TYPE=Release", f"-DPython_EXECUTABLE={sys.executable}",
            f"-DFATOORA_LIBRARY={native_library}",
            f"-DFATOORA_IMPLIB={target_dir.resolve() / 'fatoora_ffi.dll.lib'}",
        ])
        subprocess.check_call(["cmake", "--build", str(native_build), "--config", "Release", "--parallel", "2"])
        subprocess.check_call([
            "cmake", "--install", str(native_build), "--config", "Release",
            "--prefix", str(Path(self.build_lib).resolve()),
        ])

        rule_notices = package_dir / "licenses" / "zatca"
        rule_notices.mkdir(parents=True, exist_ok=True)
        for name in ("LICENSE-LGPL-3.0.txt", "LICENSE-GPL-3.0.txt", "NOTICE.md"):
            shutil.copy2(
                repo_root / "fatoora-core/tests/fixtures/business-rules" / name,
                rule_notices / name,
            )

        # Retain the notices supplied with libraries that wheel repair bundles.
        if os.name == "nt":
            vcpkg_root = Path(os.environ.get("VCPKG_INSTALLATION_ROOT", "C:/vcpkg"))
            license_files = (vcpkg_root / "installed/x64-windows/share").glob(
                "*/copyright"
            )
        elif sys.platform.startswith("linux"):
            license_files = [
                source
                for dependency in ("libxml2", "xz-libs")
                for source in (Path("/usr/share/licenses") / dependency).glob("*")
                if source.is_file()
            ]
            # AlmaLinux 8's xz-libs RPM keeps its license in the xz doc directory.
            license_files.extend(Path("/usr/share/doc/xz").glob("COPYING"))
        else:
            license_files = ()
        for source in license_files:
            dependency = "xz-libs" if source.parent.name == "xz" else source.parent.name
            destination = package_dir / "licenses" / dependency
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination / source.name)

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


class BinaryDistribution(Distribution):
    def has_ext_modules(self) -> bool:
        return True


# Stage the root licenses before setuptools collects package metadata.
license_root = build_py._resolve_repo_root()
for license_name in ("LICENSE-MIT", "LICENSE-APACHE", "THIRD_PARTY_NOTICES.md"):
    source = license_root / license_name
    if source.is_file():
        shutil.copy2(source, Path(__file__).resolve().parent / license_name)


setup(
    cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel},
    distclass=BinaryDistribution,
)
