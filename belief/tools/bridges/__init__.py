"""Built-in BELIEF tool bridges.

Imports are intentionally lazy to avoid cycles between exporters, schemas, and
bridge implementations.
"""


def builtin_bridge_classes():
    from .arjun import ArjunBridge
    from .authmatrix import AuthMatrixBridge
    from .autorize import AutorizeBridge
    from .codeql import CodeQLBridge
    from .dradis import DradisBridge
    from .evomaster import EvoMasterBridge
    from .faraday import FaradayBridge
    from .joern import JoernBridge
    from .param_miner import ParamMinerBridge
    from .restler import RestlerBridge
    from .schemathesis import SchemathesisBridge
    from .semgrep import SemgrepBridge
    from .threat_dragon import ThreatDragonBridge
    from .zap import ZAPBridge

    return [
        SemgrepBridge,
        CodeQLBridge,
        SchemathesisBridge,
        RestlerBridge,
        AuthMatrixBridge,
        AutorizeBridge,
        ArjunBridge,
        ParamMinerBridge,
        ZAPBridge,
        JoernBridge,
        EvoMasterBridge,
        DradisBridge,
        FaradayBridge,
        ThreatDragonBridge,
    ]


__all__ = ["builtin_bridge_classes"]
