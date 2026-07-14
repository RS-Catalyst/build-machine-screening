"""YAML ingestion for the packet assembler.

Reads a component definition file and returns the inner ``component`` mapping
as a plain Python dict. Parsing is kept deliberately separate from assembly and
policy so each stage can be reasoned about (and tested) on its own.
"""

from __future__ import annotations

import yaml


class IngestError(Exception):
    """Raised when the input file cannot be read or is structurally invalid."""


def load_component(path):
    """Load a YAML component definition and return its ``component`` mapping.

    Parameters
    ----------
    path : str
        Path to the YAML file.

    Returns
    -------
    dict
        The mapping found under the top-level ``component`` key.

    Raises
    ------
    IngestError
        If the file is missing, not valid YAML, or does not contain a
        ``component`` mapping.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise IngestError(f"input file not found: {path}") from exc
    except OSError as exc:
        raise IngestError(f"could not read input file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise IngestError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict) or "component" not in data:
        raise IngestError("YAML must contain a top-level 'component' mapping")

    component = data["component"]
    if not isinstance(component, dict):
        raise IngestError("'component' must be a mapping of fields")

    return component
