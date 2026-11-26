"""Declared layer for a Windows host: the uninstall registry.

Windows keeps one uninstall key per installed program under
``...\\CurrentVersion\\Uninstall`` — three of them, counting the
WOW6432Node view (32-bit programs on 64-bit Windows) and the per-user
hive. Those records are the host's *declared* inventory: written by the
installer at install time, which makes them better evidence than any
list an administrator reconstructs later — but still a claim, which is
why the observed layer (win_modules) exists to check it.

This module splits cleanly in two:

- ``parse_uninstall_keys`` is a pure function over raw record dicts, so
  it is fixture-tested on any platform.
- ``read_uninstall_registry`` is the only function that touches
  ``winreg``; it imports it lazily so this module imports cleanly on
  Linux. Its first live execution happens on a real Windows machine.
"""

from __future__ import annotations

import re

from ..model import ServiceNode

# Registry paths, relative to their hives.
_UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
_UNINSTALL_KEY_WOW = (
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

# Values read from each uninstall subkey. These are the value names
# Windows installers actually write; everything else is ignored.
_VALUE_NAMES = (
    "DisplayName",
    "DisplayVersion",
    "Publisher",
    "InstallLocation",
    "UninstallString",
    "SystemComponent",
    "ParentKeyName",
)


def normalize_pkg_name(name: str) -> str:
    """Canonical package id fragment: lowercase, separator runs -> '-'.

    Folds whitespace, underscores, and dots, which is PEP 503
    normalization for pip names and close enough for DisplayNames:
    "Microsoft Visual C++ 2019" -> "microsoft-visual-c++-2019".
    """
    return re.sub(r"[-_.\s]+", "-", str(name).strip().lower()).strip("-")


def pkg_id(name: str) -> str:
    return f"pkg:{normalize_pkg_name(name)}"


def parse_uninstall_keys(records: list[dict]) -> list[ServiceNode]:
    """Turn raw uninstall-key records into package nodes.

    Skip rules — an uninstall key is not always a product:
    - no DisplayName: not a user-facing install, nothing to name.
    - ``SystemComponent == 1``: a component Windows hides from the
      Programs list on purpose.
    - ``ParentKeyName`` present: an update or child component that
      rolls up under its parent product; counting it as its own
      package would double-count the parent.

    The same product registered in both the 64-bit and WOW6432Node
    hives is one package: dedupe on the normalized id, keep the first
    non-empty metadata, and merge the hive paths into ``sources`` so
    the duplication itself stays visible as evidence.
    """
    nodes: dict[str, ServiceNode] = {}
    for rec in records:
        name = str(rec.get("DisplayName") or "").strip()
        if not name:
            continue
        if rec.get("SystemComponent") == 1:
            continue
        if str(rec.get("ParentKeyName") or "").strip():
            continue
        nid = pkg_id(name)
        key_path = str(rec.get("KeyPath") or "")
        if nid in nodes:
            labels = nodes[nid].labels
            if key_path and key_path not in labels["sources"]:
                labels["sources"].append(key_path)
            version = str(rec.get("DisplayVersion") or "")
            if version and version != labels["version"]:
                seen = labels.setdefault("versions_seen", [labels["version"]])
                if version not in seen:
                    seen.append(version)
            for label, value in (
                ("publisher", rec.get("Publisher")),
                ("install_location", rec.get("InstallLocation")),
            ):
                if not labels.get(label) and value:
                    labels[label] = str(value)
            continue
        nodes[nid] = ServiceNode(
            id=nid,
            kind="package",
            substrate="windows-registry",
            labels={
                "version": str(rec.get("DisplayVersion") or ""),
                "publisher": str(rec.get("Publisher") or ""),
                "install_location": str(rec.get("InstallLocation") or ""),
                "sources": [key_path] if key_path else [],
            },
        )
    return sorted(nodes.values(), key=lambda n: n.id)


def read_uninstall_registry() -> list[dict]:
    """Read the raw uninstall records from this machine's registry.

    Windows only. Raises RuntimeError anywhere else — the caller
    (scan-host) treats that as "source skipped", never as a crash.
    """
    try:
        import winreg
    except ImportError as exc:  # non-Windows: winreg does not exist
        raise RuntimeError(
            "Windows registry is only available on Windows"
        ) from exc

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_KEY, "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_KEY_WOW, "HKLM\\WOW6432Node"),
        (winreg.HKEY_CURRENT_USER, _UNINSTALL_KEY, "HKCU"),
    ]
    records: list[dict] = []
    for hive, key_path, hive_name in roots:
        try:
            key = winreg.OpenKey(hive, key_path)
        except OSError:
            continue  # hive view absent on this machine; not an error
        with key:
            subcount = winreg.QueryInfoKey(key)[0]
            for i in range(subcount):
                try:
                    sub_name = winreg.EnumKey(key, i)
                    sub = winreg.OpenKey(key, sub_name)
                except OSError:
                    continue
                record: dict = {
                    "KeyPath": f"{hive_name}\\{key_path}\\{sub_name}"
                }
                with sub:
                    for value_name in _VALUE_NAMES:
                        try:
                            value, _type = winreg.QueryValueEx(sub, value_name)
                        except OSError:
                            continue  # value not written by this installer
                        record[value_name] = value
                records.append(record)
    return records


def collect_registry_packages() -> list[ServiceNode]:
    """Live convenience wrapper: read the registry, parse the nodes."""
    return parse_uninstall_keys(read_uninstall_registry())
