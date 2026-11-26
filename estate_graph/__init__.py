"""G1 Estate Graph — learned dependency truth for an estate.

A standalone producer of signed, expiring dependency graphs. It learns
what an estate's services actually depend on from observed evidence,
reconciles the learning against human declarations, and emits the result
as a DSSE-signed artifact that other systems consume by verification.
"""

from .model import SCHEMA_VERSION

__all__ = ["SCHEMA_VERSION"]
__version__ = "0.1.0"
