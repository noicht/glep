from glep.tools.base import Tool, ToolResult
from glep.tools.curl_tool import CurlTool, sqli_probe_url
from glep.tools.dig_tool import DigTool, looks_like_domain
from glep.tools.hydra_tool import HydraTool
from glep.tools.nikto_tool import NiktoTool
from glep.tools.nmap_tool import NmapTool
from glep.tools.sqlmap_tool import SqlmapTool

TOOL_REGISTRY: dict[str, Tool] = {
    tool_cls.name: tool_cls()
    for tool_cls in (
        NmapTool,
        NiktoTool,
        HydraTool,
        SqlmapTool,
        CurlTool,
        DigTool,
    )
}


def tool_availability() -> dict[str, dict]:
    """Estado de instalación de cada binario, para preflight/--check."""
    return {
        name: {
            "binary": tool.binary or name,
            "available": tool.available(),
        }
        for name, tool in TOOL_REGISTRY.items()
    }


__all__ = [
    "Tool",
    "ToolResult",
    "TOOL_REGISTRY",
    "tool_availability",
    "sqli_probe_url",
    "looks_like_domain",
]
