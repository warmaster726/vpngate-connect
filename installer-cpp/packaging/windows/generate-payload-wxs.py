#!/usr/bin/env python3
"""Generate ICE-clean WiX components for a staged per-user Windows payload."""

from __future__ import annotations

import argparse
import hashlib
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"
# Stable namespace for component GUIDs. Do not change after publishing an MSI.
COMPONENT_NAMESPACE = uuid.UUID("c1d25155-2688-41b4-8f00-5171abc46c85")
REGISTRY_KEY = r"Software\VPN Gate Connect\Installer\Components"

ET.register_namespace("", WIX_NS)


def wix_tag(name: str) -> str:
    return f"{{{WIX_NS}}}{name}"


def normalized_relative(path: Path) -> str:
    return path.as_posix().casefold()


def stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}{digest}"


def component_guid(kind: str, value: str) -> str:
    return str(uuid.uuid5(COMPONENT_NAMESPACE, f"{kind}/{value.casefold()}"))


def add_registry_keypath(component: ET.Element, name: str) -> None:
    ET.SubElement(
        component,
        wix_tag("RegistryValue"),
        {
            "Root": "HKCU",
            "Key": REGISTRY_KEY,
            "Name": name,
            "Type": "integer",
            "Value": "1",
            "KeyPath": "yes",
        },
    )


def add_directory_payload(parent: ET.Element, payload_dir: Path, relative_dir: Path) -> None:
    """Add a folder cleanup component, each file component, and child directories."""
    relative_text = normalized_relative(relative_dir) if relative_dir.parts else "."

    cleanup = ET.SubElement(
        parent,
        wix_tag("Component"),
        {
            "Id": stable_id("CLEAN", relative_text),
            "Guid": component_guid("directory", relative_text),
            "Feature": "MainFeature",
        },
    )
    add_registry_keypath(cleanup, stable_id("dir_", relative_text))
    ET.SubElement(
        cleanup,
        wix_tag("RemoveFolder"),
        {"Id": stable_id("REMOVE", relative_text), "On": "uninstall"},
    )

    source_dir = payload_dir.joinpath(*relative_dir.parts)
    files = sorted(
        (entry for entry in source_dir.iterdir() if entry.is_file()),
        key=lambda entry: entry.name.casefold(),
    )
    for file_path in files:
        relative_file = file_path.relative_to(payload_dir)
        relative_file_text = normalized_relative(relative_file)
        component = ET.SubElement(
            parent,
            wix_tag("Component"),
            {
                "Id": stable_id("COMP", relative_file_text),
                "Guid": component_guid("file", relative_file_text),
                "Feature": "MainFeature",
            },
        )
        add_registry_keypath(component, stable_id("file_", relative_file_text))
        file_id = (
            "InstallerExecutable"
            if relative_file_text == "vpngate-installer.exe"
            else stable_id("FILE", relative_file_text)
        )
        source = str(file_path.resolve()).replace("/", "\\")
        ET.SubElement(
            component,
            wix_tag("File"),
            {"Id": file_id, "Source": source},
        )

    directories = sorted(
        (entry for entry in source_dir.iterdir() if entry.is_dir()),
        key=lambda entry: entry.name.casefold(),
    )
    for child in directories:
        child_relative = relative_dir / child.name
        child_id = stable_id("D", normalized_relative(child_relative))
        child_element = ET.SubElement(
            parent,
            wix_tag("Directory"),
            {"Id": child_id, "Name": child.name},
        )
        add_directory_payload(child_element, payload_dir, child_relative)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    payload_dir = args.payload_dir.resolve(strict=True)
    if not payload_dir.is_dir():
        parser.error(f"payload directory does not exist: {payload_dir}")
    helper = payload_dir / "vpngate-installer.exe"
    if not helper.is_file():
        parser.error(f"required helper is missing: {helper}")

    files = [path for path in payload_dir.rglob("*") if path.is_file()]
    if not files:
        parser.error(f"payload directory is empty: {payload_dir}")

    wix = ET.Element(wix_tag("Wix"))
    fragment = ET.SubElement(wix, wix_tag("Fragment"))
    directory_ref = ET.SubElement(
        fragment, wix_tag("DirectoryRef"), {"Id": "INSTALLDIR"}
    )
    add_directory_payload(directory_ref, payload_dir, Path())

    args.output.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(wix)
    tree.write(args.output, encoding="utf-8", xml_declaration=True)
    print(f"Generated WiX payload authoring for {len(files)} files: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
