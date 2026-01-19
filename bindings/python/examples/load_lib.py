from __future__ import annotations

from fatoora import FfiLibrary


def main() -> None:
    ffi = FfiLibrary()
    cfg = ffi.lib.fatoora_config_new(0)
    print("config handle:", cfg)
    ffi.lib.fatoora_config_free(cfg)


if __name__ == "__main__":
    main()
