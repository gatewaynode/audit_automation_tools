#!/usr/bin/env python3.7
"""A quick little program to automate package audits.

@author u/gatewaynode
@website r/pipsecurity
"""

import os
import sys
import subprocess
import string
import click
import tarfile
import zipfile
import traceback
import logging
from pprint import pprint


def dateutil_quirk_handler(raw_dir_list):
    scan_list = []
    for file in raw_dir_list:
        if file.startswith("python_dateutil") and not file.endswith(".whl"):
            scan_list.append(file)
    scan_list.append("dateutil")
    return scan_list


def pyyaml_quirk_handler(raw_dir_list):
    scan_list = []
    for file in raw_dir_list:
        if file.startswith("PyYAML") and not file.endswith(".tar.gz"):
            scan_list.append(file)
    return scan_list


def init():
    if not os.path.isdir("local_files"):
        os.makedirs("local_files")


@click.command()
@click.option("-p", "--package", "raw_input", help="The PyPI package to audit")
@click.option("-v", "--verbose", "verbose", help="Show more information.", is_flag=True)
@click.option("-d", "--debug", "debug", help="Internal data information.", is_flag=True)
@click.option(
    "-j",
    "--json",
    "output_json",
    help="Run scanners with JSON output.  Disables verbose.",
    is_flag=True,
)
def main(raw_input, verbose, debug, output_json):
    scan_list = []
    # Sanitize input (ref: https://www.python.org/dev/peps/pep-0008/#package-and-module-names)
    exclude = set(string.punctuation.replace("_", "").replace("-", "") + " ")
    input = "".join(character for character in raw_input if character not in exclude)

    download_package = [
        "pip3",
        "download",
        "--no-binary",
        "--no-deps",
        "--dest",
        "local_files",
        input,
    ]

    if verbose and not output_json:
        print(f"Using pip to grab {input} package.")
    try:
        output = subprocess.run(download_package, capture_output=True)
    except Exception as e:
        logging.error(traceback.format_exc())
        sys.exit(1)
    
    # Handle the downloaded file
    if output:
        if debug:
            pprint(output)
        stdout = output.stdout.decode("utf-8")
        if "Saved " in stdout:
            saved_file_name = stdout.split("Saved ")[1].split("\n")[0].replace("./", "")
        else:
            print("File already downloaded or pip transaction failed!")
            sys.exit(1)
        if saved_file_name.endswith(".whl"):
            if verbose and not output_json:
                print(f"Unzipping downloaded wheel: {saved_file_name}")
            zip_ref = zipfile.ZipFile(saved_file_name, "r")
            try:
                zip_ref.extractall("local_files/")
            except Exception as e:
                logging.error(traceback.format_exc())
                zip_ref.close()
                sys.exit(1)
            zip_ref.close()
        elif saved_file_name.endswith(".tar.gz"):
            if verbose and not output_json:
                print(f"Extracting tarball: {saved_file_name}")
            tar_ref = tarfile.open(saved_file_name, "r")
            try:
                tar_ref.extractall("local_files/")
            except Exception as e:
                logging.error(traceback.format_exc())
                tar_ref.close()
                sys.exit(1)
            tar_ref.close()
        else:
            if verbose and not output_json:
                print(f"{saved_file_name} found. Not a wheel or tarball, can't handle anything else yet. Exiting.")
            sys.exit(1)
        
        # Create scanning list
        raw_dir_list = os.listdir("local_files")

        """ Quirk handler.  This will change as this is not scalable 
            Note: requests ignores "--no-deps"
        """
        if input == "python-dateutil":
            scan_list = dateutil_quirk_handler(raw_dir_list)
        elif input == "pyyaml":
            scan_list = pyyaml_quirk_handler(raw_dir_list)
        else:
            for file in raw_dir_list:
                if file.startswith(input) and not file.endswith(".whl"):
                    scan_list.append(file)

        if verbose and not output_json:
            print(f"Running bandit against package dirs {', '.join(scan_list)}")
        for target in scan_list:
            if output_json:
                bandit_scan = [
                    "bandit",
                    "-r",
                    "-q",
                    "-f",
                    "json",
                    "-o",
                    f"local_files/bandit_scan_{target}.json",
                    f"local_files/{target}",
                ]
            else:
                bandit_scan = [
                    "bandit",
                    "-r",
                    "-q",
                    "-f",
                    "txt",
                    "-o",
                    f"local_files/bandit_scan_{target}.txt",
                    f"local_files/{target}",
                ]
            try:
                subprocess.run(bandit_scan)
            except Exception as e:
                logging.error(traceback.format_exc())

        if verbose and not output_json:
            print(f"Running detect-secrets against package dirs {', '.join(scan_list)}")
        for target in scan_list:
            detect_secrets_scan = [
                "detect-secrets",
                "scan",
                "--all-files",
                f"local_files/{target}",
            ]
            try:
                output = subprocess.run(detect_secrets_scan, capture_output=True)
            except Exception as e:
                logging.error(traceback.format_exc())
            try:
                file = open(f"local_files/detect_secrets_{target}.json", "w")
                file.write(output.stdout.decode("utf-8"))
                file.close()
            except Exception as e:
                logging.error(traceback.format_exc())


if __name__ == "__main__":
    init()
    main()
