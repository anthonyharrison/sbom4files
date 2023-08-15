# SBOM4Files

SBOM4Files generates a SBOM (Software Bill of Materials) for a directory in a number of formats including
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).
It identifies all files within a directory and includes license and copyright information, where possible, for each file.

It is intended to be used as part of a continuous integration system to enable accurate records of SBOMs to be maintained, typically through the
build development phase, and also to support subsequent audit needs to determine if a particular component has been used.

## Installation

To install use the following command:

`pip install sbom4files`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

### Issues with Windows Installation

When running on Windows, if you get the following error

`ImportError: failed to find libmagic.  Check your installation`

This is because of a mismatch with the installation of the magic library. To resolve, please issue the following commands

```bash
pip uninstall python-magic
pip uninstall python-magic-bin

pip install python-magic
pip install python-magic-bin
```

## Usage

```
usage: sbom4files [-h] [-d DIRECTORY] [-p PROJECT] [-r] [--debug] 
                  [--sbom {spdx,cyclonedx}] [--format {tag,json,yaml}] 
                  [-o OUTPUT_FILE] [-V]

```

```
options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

Input:
  -d DIRECTORY, --directory DIRECTORY
                        Directory to be scanned
  -p PROJECT, --project PROJECT
                        Name of project
  -r, --recurse         Recurse directories

Output:
  --debug               add debug information
  --sbom {spdx,cyclonedx}
                        specify type of sbom to generate (default: spdx)
  --format {tag,json,yaml}
                        format for SPDX software bill of materials (sbom) (default: tag)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output filename (default: output to stdout)

```
					
## Operation

The `--directory` option is used to identify the directory to be scanned. If this option is not specified, the current directory is assumed.
Specifying the `--recurse` option will result in the files in subdirectories being included in the generation of the SBOM.

The `--project` option is used to specify the name of a project to be referenced in the generated SBOM. This option must be specified.

The `--sbom` option is used to specify the format of the generated SBOM (the default is SPDX). The `--format` option
can be used to specify the formatting of the SPDX SBOM (the default is Tag Value format but JSON and YAML format is also supported).
All CycloneDX SBOMs are generated in JSON format.

The `--output-file` option is used to control the destination of the output generated by the tool. The
default is to report to the console but can be stored in a file (specified using `--output-file` option).

The application will attempt to extract the license and copyright information for each file. 

Checksums in SHA1, SHA256 and SHA512 formats are generated for each file.

## Licence

Licenced under the Apache 2.0 Licence.

## Limitations

This tool is meant to support software development and security audit functions. The usefulness of the tool is dependent on the SBOM data
which is provided to the tool. Unfortunately, the tool is unable to determine the validity or completeness of such a SBOM file; users of the tool
are therefore reminded that they should assert the quality of any data which is provided to the tool.

When processing and validating licenses, the application will use a set of synonyms to attempt to map some license identifiers to the correct [SPDX License Identifiers](https://spdx.org/licenses/). However, the
user of the tool is reminded that they should assert the quality of any data which is provided by the tool particularly where the license identifier has been modified.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.