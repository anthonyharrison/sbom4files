# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import hashlib
import mimetypes

from lib4sbom.data.file import SBOMFile
from lib4sbom.license import LicenseScanner

class FileScanner:

    def __init__(self, debug = False):
        self.sbom_file = SBOMFile()
        self.licensescanner = LicenseScanner()
        self.debug = False
        self.id = 0

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
                        if self.licensescanner.find_license(license) != "UNKNOWN":
                            if found_license is None:
                                found_license = [license]
                            else:
                                found_license.append(license)
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
        # check if it is a file
        processed = False
        self.sbom_file.initialise()
        if filename.is_file():
            processed = True
            self.sbom_file.set_name(str(filename))
            self.sbom_file.set_id("SPDXRef-File-" + str(self.id).zfill(4))
            self.id += 1
            # Attempt to determine file type
            (mimetype, _) = mimetypes.guess_type(str(filename))
            if mimetype is not None:
                self.sbom_file.set_filetype(mimetype.split("/")[0])
            else:
                self.sbom_file.set_filetype("other")
            # Checksum file
            file_hash_1, file_hash_256, file_hash_512 = self._generate_checksum(filename)
            self.sbom_file.set_checksum("SHA1", file_hash_1)
            self.sbom_file.set_checksum("SHA256", file_hash_256)
            self.sbom_file.set_checksum("SHA512", file_hash_512)
            # Attempt to determine license information
            if self.debug:
                print(f"Processing {filename} {mimetype}")
            found_license, found_copyright, copyright_text = self._find_licence(filename)

            if found_license is not None:
                for license in found_license:
                    self.sbom_file.set_licenseinfoinfile(license)
                    self.sbom_file.set_licensecomment(
                    "<text>This information was automatically"
                    " extracted from the file.</text>"
                    )
                if len(found_license) == 1:
                    self.sbom_file.set_licenseconcluded(found_license[0])
                else:
                    concluded_licence = " AND ".join(f for f in found_license)
                    self.sbom_file.set_licenseconcluded(concluded_licence)
            else:
                # Default licence status
                self.sbom_file.set_licenseinfoinfile("NONE")
                self.sbom_file.set_licensecomment(
                    "<text>Unable to determine license from the file.</text>"
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

