# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import pathlib
import sys
import textwrap
from collections import ChainMap

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM

from sbom4files.filescanner import FileScanner
from sbom4files.version import VERSION

# CLI processing


def main(argv=None):
    argv = argv or sys.argv
    app_name = "sbom4files"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOM4Files generates a Software Bill of Materials for the
            files within a directory.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-d",
        "--directory",
        action="store",
        default="",
        help="Directory to be scanned",
    )
    input_group.add_argument(
        "-p",
        "--project",
        action="store",
        default="",
        help="Name of project",
    )
    input_group.add_argument(
        "-r",
        "--recurse",
        action="store_true",
        default=False,
        help="Recurse directories",
    )
    input_group.add_argument(
        "-i",
        "--ignore",
        action="store",
        default="",
        help="Comma separated list of extensions to ignore",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="format for SPDX software bill of materials (sbom) (default: tag)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "directory": "",
        "project": "",
        "ignore": "",
        "output_file": "",
        "recurse": False,
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    directory_location = args["directory"]

    if directory_location == "":
        # Assume current directory
        directory_location = os.getcwd()

    if args["sbom"] == "spdx":
        bom_format = args["format"]
    else:
        bom_format = "json"

    if args["project"] == "":
        print("[ERROR] Project name must be specified.")
        return -1

    if args["debug"]:
        print("SBOM type", args["sbom"])
        print("Format", bom_format)
        print("Output file", args["output_file"])
        print("Directory", directory_location)
        print("Project", args["project"])
        print("Ignore file extensions", args["ignore"])

    # Find files
    file_dir = pathlib.Path(directory_location)

    if not file_dir.exists():
        print("[ERROR] Directory not found.")
        return -1

    # iterate directory and assemble SBOM items
    file_scanner = FileScanner(args["debug"], args["ignore"])
    sbom_files = {}
    sbom_packages = {}
    sbom_relationships = []
    sbom_relationship = SBOMRelationship()

    # Create root package
    sbom_package = SBOMPackage()
    package_name = f'{args["project"].replace(" ","-")}-files'
    sbom_package.set_name(package_name)
    sbom_package.set_id(package_name)
    sbom_package.set_filesanalysis(True)
    sbom_packages[
        (sbom_package.get_name(), sbom_package.get_value("version"))
    ] = sbom_package.get_package()
    package_id = sbom_package.get_value("id")
    package = sbom_package.get_name()
    # And add relationship to root package
    sbom_relationship.initialise()
    sbom_relationship.set_relationship(args["project"], "DESCRIBES", package)
    sbom_relationships.append(sbom_relationship.get_relationship())

    file_process = {False: file_dir.iterdir(), True: file_dir.glob("**/*")}
    # iterdir() for current directory
    # Use glob() for recursive file_dir.glob('**/*'):
    # for entry in file_dir.iterdir():
    for entry in file_process[args["recurse"]]:
        if file_scanner.scan_file(entry):
            sbom_files[file_scanner.get_name()] = file_scanner.get_file()
            # Add relationship
            sbom_relationship.initialise()
            sbom_relationship.set_relationship(
                package, "CONTAINS", file_scanner.get_name()
            )
            sbom_relationship.set_relationship_id(
                package_id, file_scanner.get_value("id")
            )
            sbom_relationship.set_target_type("file")
            sbom_relationships.append(sbom_relationship.get_relationship())

    # Lifecycle is always pre-build
    sbom_document = SBOMDocument()
    sbom_document.set_value("lifecycle", "pre-build")

    # Generate SBOM file
    files_sbom = SBOM()
    files_sbom.add_document(sbom_document.get_document())
    files_sbom.add_files(sbom_files)
    files_sbom.add_packages(sbom_packages)
    files_sbom.add_relationships(sbom_relationships)

    sbom_gen = SBOMGenerator(
        sbom_type=args["sbom"], format=bom_format, application=app_name, version=VERSION
    )
    sbom_gen.generate(
        project_name=args["project"],
        sbom_data=files_sbom.get_sbom(),
        filename=args["output_file"],
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
