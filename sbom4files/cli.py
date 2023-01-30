# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import hashlib
import mimetypes
import os
import pathlib
import sys
import textwrap
from collections import ChainMap

from lib4sbom.data.file import SBOMFile
from lib4sbom.generator import SBOMGenerator
from lib4sbom.license import LicenseScanner
from lib4sbom.sbom import SBOM
from lib4sbom.version import VERSION

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

    # Find files
    file_dir = pathlib.Path(directory_location)

    # iterate directory and assemble SBOM items
    sbom_file = SBOMFile()
    sbom_files = {}

    licensescanner = LicenseScanner()
    id = 0
    file_process = {False: file_dir.iterdir(), True: file_dir.glob("**/*")}
    # iterdir() for current directory
    # Use glob() for recursive file_dir.glob('**/*'):
    # for entry in file_dir.iterdir():
    for entry in file_process[args["recurse"]]:
        # check if it is a file
        if entry.is_file():
            sbom_file.initialise()
            sbom_file.set_name(str(entry))
            sbom_file.set_id("SPDXRef-File-" + str(id).zfill(4))
            id += 1
            # Attempt to determine file type
            (mimetype, _) = mimetypes.guess_type(str(entry))
            if mimetype is not None:
                sbom_file.set_filetype(mimetype.split("/")[0])
            else:
                sbom_file.set_filetype("other")
            # Calculate checksums for the file
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            sha512_hash = hashlib.sha512()
            with open(entry, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha1_hash.update(byte_block)
                    sha256_hash.update(byte_block)
                    sha512_hash.update(byte_block)
                file_hash_1 = sha1_hash.hexdigest()
                file_hash_256 = sha256_hash.hexdigest()
                file_hash_512 = sha512_hash.hexdigest()
            sbom_file.set_checksum("SHA1", file_hash_1)
            sbom_file.set_checksum("SHA256", file_hash_256)
            sbom_file.set_checksum("SHA512", file_hash_512)
            # Attempt to determine license information
            if args["debug"]:
                print(f"Processing {entry} {mimetype}")
            found_license = None
            found_copyright = False
            with open(entry, "r") as f:
                try:
                    # Binary files are likely to fail call to readlines()
                    lines = f.readlines()
                    for line in lines:
                        # Search for SPDX licence string
                        if "SPDX-License-Identifier:" in line:
                            license = (
                                line.split("SPDX-License-Identifier:", 1)[1]
                                .strip()
                                .rstrip("\n")
                            )
                            # Only include if valid license
                            if licensescanner.find_license(license) != "UNKNOWN":
                                sbom_file.set_licenseinfoinfile(license)
                                sbom_file.set_licensecomment(
                                    "<text>This information was automatically"
                                    " extracted from the file.</text>"
                                )
                                if found_license is None:
                                    found_license = license
                                else:
                                    found_license = found_license + " AND " + license
                        elif "Copyright" in line and not found_copyright:
                            copyright_text = (
                                line.split("Copyright", 1)[1].strip().rstrip("\n")
                            )
                            sbom_file.set_copyrighttext(
                                f"<text> Copyright {copyright_text}</text>"
                            )
                            found_copyright = True
                except Exception as e:
                    if args["debug"]:
                        print(f"{e}")
            # Update licence status
            if found_license is not None:
                sbom_file.set_licenseconcluded(found_license)
            else:
                # Default licence status
                sbom_file.set_licenseconcluded("NOASSERTION")
                sbom_file.set_licenseinfoinfile("NONE")
                sbom_file.set_licensecomment(
                    "<text>Unable to determine license from the file.</text>"
                )
            if not found_copyright:
                sbom_file.set_copyrighttext("NOASSERTION")
            sbom_files[sbom_file.get_name()] = sbom_file.get_file()

    # Generate SBOM file
    my_sbom = SBOM()
    my_sbom.add_files(sbom_files)

    sbom_gen = SBOMGenerator(sbom_type=args["sbom"], format=bom_format)
    sbom_gen.generate(
        project_name=args["project"],
        sbom_data=my_sbom.get_sbom(),
        filename=args["output_file"],
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
