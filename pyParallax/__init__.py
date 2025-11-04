from . import pyparallax_core as _core 

format = _core.format
open = _core.open
put = _core.put
get = _core.get
close = _core.close
metrics = _core.metrics

class _Opts:
    PAR_CREATE_DB = _core.PAR_CREATE_DB
    PAR_DONOT_CREATE_DB = _core.PAR_DONOT_CREATE_DB

opts = _Opts()

__all__ = [
        "format",
        "open",
        "put",
        "get",
        "close",
        "metrics",
        "opts"
]

del _core
