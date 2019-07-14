#!/usr/bin/env python3.7
"""A quick little program to automate package audits.

@author u/gatewaynode
@website https://reddit.com/r/pipsecurity
"""

import os
import sys
import subprocess
import string
import click
import json
import tarfile
import zipfile
import traceback
import logging
from pprint import pprint


def init():
    if not os.path.isdir("local_files"):
        os.makedirs("local_files")


def _decode_json_file(input_list, verbose=False, debug=False, output_json=False):
    try:
        with open(input_list, "r") as file:
            targets_from_file = json.load(file)
    except Exception as e:
        logging.error(traceback.format_exc())
        return False

    return targets_from_file


def _pip_download(raw_input, output_dir, verbose=False, debug=False, output_json=False):
    # Sanitize input (ref: https://www.python.org/dev/peps/pep-0008/#package-and-module-names)
    exclude = set(string.punctuation.replace("_", "").replace("-", "") + " ")
    input = "".join(character for character in raw_input if character not in exclude)

    download_package = [
        "pip3",
        "download",
        "--no-binary",
        "--no-deps",
        "--dest",
        output_dir,
        input,
    ]

    try:
        output = subprocess.run(download_package, capture_output=True)
    except Exception as e:
        logging.error(traceback.format_exc())
        return False

    return output


def _extract_archives(
    output, output_dir, package_meta, verbose=False, debug=False, output_json=False
):
    stdout = output.stdout.decode("utf-8")
    if "Saved " in stdout:
        saved_file_name = stdout.split("Saved ")[1].split("\n")[0].replace("./", "")
    else:
        print("File already downloaded or pip transaction failed!")
        return False
    if saved_file_name.endswith(".whl"):
        if verbose and not output_json:
            print(f"Unzipping downloaded wheel: {saved_file_name}")
        zip_ref = zipfile.ZipFile(saved_file_name, "r")
        package_meta["total_package_files"] = len(zip_ref.namelist())
        parsed_raw_dir_list = list(
            file for file in zip_ref.namelist() if file.endswith(".py")
        )

        try:
            zip_ref.extractall(f"{output_dir}/")
        except Exception as e:
            logging.error(traceback.format_exc())
            zip_ref.close()
            return (False, package_meta)

        zip_ref.close()
        return (parsed_raw_dir_list, package_meta)

    elif saved_file_name.endswith(".tar.gz"):
        if verbose and not output_json:
            print(f"Extracting tarball: {saved_file_name}")
        tar_ref = tarfile.open(saved_file_name, "r")
        package_meta["total_package_files"] = len(tar_ref.getnames())
        parsed_raw_dir_list = list(
            file for file in tar_ref.getnames() if file.endswith(".py")
        )

        try:
            tar_ref.extractall(f"{output_dir}/")
        except Exception as e:
            logging.error(traceback.format_exc())
            tar_ref.close()
            return (False, package_meta)

        tar_ref.close()
        return (parsed_raw_dir_list, package_meta)

    else:
        if verbose and not output_json:
            print(
                f"{saved_file_name} found. Not a wheel or tarball, can't handle anything else yet."
            )
        return False


def _retrieve_directories_to_scan(
    parsed_raw_dir_list, package_meta, verbose=False, debug=False, output_json=False
):
    if parsed_raw_dir_list:
        package_meta["total_python_files"] = len(parsed_raw_dir_list)
        scan_list = list(set(dir.split("/")[0] for dir in parsed_raw_dir_list))
    else:
        if verbose and not output_json:
            print("No python files found in package.  Exiting")
        return False

    return (scan_list, package_meta)


def _bandit_scan(scan_list, output_dir, verbose=False, debug=False, output_json=False):
    scan_errors = 0
    for target in scan_list:
        if output_json:
            bandit_scan = [
                "bandit",
                "-r",
                "-q",
                "-f",
                "json",
                "-o",
                f"{output_dir}/bandit_scan_{target}.json",
                f"{output_dir}/{target}",
            ]
        else:
            bandit_scan = [
                "bandit",
                "-r",
                "-q",
                "-f",
                "txt",
                "-o",
                f"{output_dir}/bandit_scan_{target}.txt",
                f"{output_dir}/{target}",
            ]
        try:
            subprocess.run(bandit_scan)
        except Exception as e:
            logging.error(traceback.format_exc())
            scan_errors += 1

    return scan_errors


def _detect_secrets_scan(
    scan_list, output_dir, verbose=False, debug=False, output_json=False
):
    scan_errors = 0
    for target in scan_list:
        detect_secrets_scan = [
            "detect-secrets",
            "scan",
            "--all-files",
            f"{output_dir}/{target}",
        ]
        try:
            detect_secrets_output = subprocess.run(
                detect_secrets_scan, capture_output=True
            )
        except Exception as e:
            logging.error(traceback.format_exc())
            scan_errors += 1

        if debug:
            print("Trying to write to:")
            pprint(f"{output_dir}/detect_secrets_{target}.json")
        try:
            file = open(f"{output_dir}/detect_secrets_{target}.json", "w")
            file.write(detect_secrets_output.stdout.decode("utf-8"))
            file.close()
        except Exception as e:
            logging.error(traceback.format_exc())
            scan_errors += 1

    return scan_errors


@click.command()
@click.option("-p", "--package", "package_name", help="The PyPI package to audit")
@click.option(
    "-o",
    "--output",
    "output_dir",
    help="The directory to unarchive into.",
    default="local_files",
)
@click.option("-v", "--verbose", "verbose", help="Show more information.", is_flag=True)
@click.option("-d", "--debug", "debug", help="Internal data information.", is_flag=True)
@click.option(
    "-j",
    "--json",
    "output_json",
    help="Run scanners with JSON output.  Disables verbose.",
    is_flag=True,
)
@click.option(
    "-i",
    "--input",
    "input_list",
    help="Input list file, in json format, of packages to scan.",
)
def main(package_name, output_dir, verbose, debug, output_json, input_list):
    # Normalize targeting options
    targets = []
    if package_name:
        targets.append(package_name)
    elif input_list:
        targets = _decode_json_file(input_list)
    # else:
    # targets = _pull_from_queue()

    # Fire!
    for raw_input in targets:
        scan_list = []
        package_meta = {}

        if verbose and not output_json:
            print(f"-> Using pip to download {raw_input}")
        if debug:
            pprint(raw_input)
        output = _pip_download(
            raw_input=raw_input,
            output_dir=output_dir,
            verbose=verbose,
            debug=debug,
            output_json=output_json,
        )

        if verbose and not output_json:
            print("-> Extracting archives and meta")
        if debug:
            pprint(output)
        if output:
            parsed_raw_dir_list, package_meta = _extract_archives(
                output=output, output_dir=output_dir, package_meta=package_meta, verbose=verbose, debug=debug, output_json=output_json
            )
            
            if verbose and not output_json:
                print("-> Parsing out the scan list")
            if debug:
                pprint(parsed_raw_dir_list)
            if parsed_raw_dir_list:
                scan_list, package_meta = _retrieve_directories_to_scan(
                    parsed_raw_dir_list=parsed_raw_dir_list, 
                    package_meta=package_meta, 
                    verbose=verbose, 
                    debug=debug, 
                    output_json=output_json
                    )

                if scan_list and package_meta:
                    if verbose and not output_json:
                        print(
                            f"-> Running bandit against files {', '.join(scan_list)}. Output saved to {output_dir}."
                        )
                    if debug:
                        pprint(scan_list)
                    bandit_scan_results = _bandit_scan(
                        scan_list=scan_list, output_dir=output_dir, output_json=output_json
                    )

                    if verbose and not output_json:
                        print(
                            f"Running detect-secrets against package dirs {', '.join(scan_list)}.  Output saved to {output_dir}."
                        )
                    if debug:
                        pprint(scan_list)
                    detect_secrets_scan_results = _detect_secrets_scan(
                        scan_list=scan_list, output_dir=output_dir, output_json=output_json
                    )


if __name__ == "__main__":
    init()  # @TODO move this to inside main, assume this is not usually needed
    main()
