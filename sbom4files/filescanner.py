# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import hashlib
from pathlib import Path

import magic
from lib4sbom.data.file import SBOMFile
from lib4sbom.license import LicenseScanner


class FileScanner:
    """
    Simple SBOM Generator for file.
    """

    def __init__(self, debug=False, extensions=""):
        self.sbom_file = SBOMFile()
        self.licensescanner = LicenseScanner()
        self.debug = debug
        self.id = 1
        # Build list of extensions to ignore
        self.extensions = []
        for e in extensions.split(","):
            if len(e) > 0:
                self.extensions.append(e)

        if self.debug:
            print("Ignoring file extensions")
            for e in self.extensions:
                print(e)

        # Load mapping of file extensions to SPDX file types (non-Mime)
        file_types_file = (
            Path(__file__).resolve().parent / "filetypes" / "filetypes.txt"
        )
        self.file_types = {}
        with open(file_types_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("["):
                    type = line.replace("[", "").replace("]", "").strip()
                    self.file_types[type] = []
                else:
                    self.file_types[type].append(line.strip())

    def _generate_checksum(self, filename):
        # Calculate checksums for the file
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        sha512_hash = hashlib.sha512()
        with open(filename, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha1_hash.update(byte_block)
                sha256_hash.update(byte_block)
                sha512_hash.update(byte_block)
            file_hash_1 = sha1_hash.hexdigest()
            file_hash_256 = sha256_hash.hexdigest()
            file_hash_512 = sha512_hash.hexdigest()
        return file_hash_1, file_hash_256, file_hash_512

    def _find_licence(self, filename):
        found_license = None
        found_copyright = False
        copyright_text = ""
        with open(filename, "r") as f:
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
                        validated_license = self.licensescanner.find_license(license)
                        if validated_license != "NOASSERTION":
                            if found_license is None:
                                found_license = [validated_license]
                            else:
                                found_license.append(validated_license)
                    elif "SPDX-FileCopyrightText:" in line and not found_copyright:
                        copyright_text = (
                            line.split("SPDX-FileCopyrightText:", 1)[1]
                            .strip()
                            .rstrip("\n")
                        )
                        found_copyright = True
                    elif "Copyright" in line and not found_copyright:
                        copyright_text = (
                            line.split("Copyright", 1)[1].strip().rstrip("\n")
                        )
                        found_copyright = True
            except Exception as e:
                if self.debug:
                    print(f"{e}")
        return found_license, found_copyright, copyright_text

    def scan_file(self, filename):
        processed = False
        self.sbom_file.initialise()
        # Check if extension is to be ignored
        if any(str(Path(filename)).endswith(ext) for ext in self.extensions):
            if self.debug:
                print(f"{str(Path(filename))} is being ignored")
            return processed
        # Only process if it is a file
        if filename.is_file():
            processed = True
            # Make absolute filename relative to current directory
            cwd = str(Path.cwd())
            relfilename = str(filename).replace(cwd, ".")
            self.sbom_file.set_name(relfilename)
            self.sbom_file.set_id(str(self.id) + "-" + Path(filename).stem)
            self.id += 1
            # Attempt to determine type of file
            file_categorised = False
            # Look for non-Mime type files
            for type in self.file_types:
                for ext in self.file_types[type]:
                    if str(filename).endswith(ext):
                        self.sbom_file.set_filetype(type)
                        file_categorised = True
                        if type == "source":
                            # Attempt to work out language
                            language_type = {
                                ".c": "C",
                                ".cc": "C++",
                                ".cpp": "C++",
                                ".cs": "C#",
                                ".css": "CSS",
                                ".cxx": "C++",
                                ".go": "Go",
                                ".h": "C",
                                ".htm": "HTML",
                                ".html": "HTML",
                                ".java": "Java",
                                ".js": "Javascript",
                                ".php": "PHP",
                                ".pl": "Perl",
                                ".py": "Python",
                                ".vb": "Visual Basic",
                            }
                            if ext in language_type:
                                if self.debug:
                                    print(
                                        f"{str(filename)} is a {language_type[ext]} file"
                                    )
                                self.sbom_file.set_comment(
                                    f"Source is {language_type[ext]}"
                                )
                        break
            mimetype = magic.from_file(str(filename), mime=True)
            if mimetype is not None:
                # Mime type detected
                self.sbom_file.set_filetype(mimetype.split("/")[0])
            elif not file_categorised:
                self.sbom_file.set_filetype("other")
            # Checksum file
            file_hash_1, file_hash_256, file_hash_512 = self._generate_checksum(
                filename
            )
            self.sbom_file.set_checksum("SHA1", file_hash_1)
            self.sbom_file.set_checksum("SHA256", file_hash_256)
            self.sbom_file.set_checksum("SHA512", file_hash_512)
            # Attempt to determine license information
            if self.debug:
                print(f"Processing {filename} {mimetype}")
            found_license, found_copyright, copyright_text = self._find_licence(
                filename
            )
            if found_license is not None:
                for license in found_license:
                    self.sbom_file.set_licenseinfoinfile(license)
                    license_comment = (
                        "This information was automatically extracted from the file."
                    )
                    if self.licensescanner.deprecated(license):
                        license_comment = (
                            f"{license_comment} {license} is now deprecated."
                        )
                    self.sbom_file.set_licensecomment(license_comment)
                if len(found_license) == 1:
                    self.sbom_file.set_licenseconcluded(found_license[0])
                else:
                    concluded_licence = " AND ".join(f for f in found_license)
                    self.sbom_file.set_licenseconcluded(concluded_licence)
            else:
                # Default licence status
                self.sbom_file.set_licenseinfoinfile("NONE")
                self.sbom_file.set_licensecomment(
                    "Unable to determine license from the file."
                )
                self.sbom_file.set_licenseconcluded("NOASSERTION")
            if not found_copyright:
                self.sbom_file.set_copyrighttext("NOASSERTION")
            else:
                self.sbom_file.set_copyrighttext(copyright_text)
        return processed

    def get_file(self):
        return self.sbom_file.get_file()

    def get_name(self):
        return self.sbom_file.get_name()

    def get_value(self, attribute):
        return self.sbom_file.get_value(attribute)
