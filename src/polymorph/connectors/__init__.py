from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .database import DatabaseConnector
    from .excel import ExcelConnector
    from .http_json import HttpEndpoint, HttpJsonConnector
    from .json_file import JsonFileConnector

_EXPORTS = {
    "DatabaseConnector": (".database", "DatabaseConnector"),
    "ExcelConnector": (".excel", "ExcelConnector"),
    "HttpEndpoint": (".http_json", "HttpEndpoint"),
    "HttpJsonConnector": (".http_json", "HttpJsonConnector"),
    "JsonFileConnector": (".json_file", "JsonFileConnector"),
}

__all__ = [
    "DatabaseConnector",
    "ExcelConnector",
    "HttpEndpoint",
    "HttpJsonConnector",
    "JsonFileConnector",
]


def __getattr__(name: str) -> object:
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *_EXPORTS))
