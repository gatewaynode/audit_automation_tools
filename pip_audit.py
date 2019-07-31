#!/usr/bin/env python3.7
"""A quick little program to automate package audits.

@author u/gatewaynode
@website https://reddit.com/r/pipsecurity
"""

import os
import sys
import shutil
import subprocess
import string
import click
import json
import tarfile
import zipfile
import traceback
import logging
from yapsy.PluginManager import PluginManager
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
        package_meta["saved_file_name"] = (
            stdout.split("Saved ")[1].split("\n")[0].replace("./", "")
        )
    else:
        print("File already downloaded or pip transaction failed!")
        return (False, package_meta)
    if package_meta["saved_file_name"].endswith(".whl"):
        if verbose and not output_json:
            print(f"-> Unzipping downloaded wheel: {package_meta['saved_file_name']}")
        zip_ref = zipfile.ZipFile(package_meta["saved_file_name"], "r")
        package_meta["archive_file_list"] = zip_ref.namelist()
        package_meta["total_package_files"] = len(package_meta["archive_file_list"])
        parsed_raw_dir_list = list(
            file for file in package_meta["archive_file_list"] if file.endswith(".py")
        )

        try:
            zip_ref.extractall(f"{output_dir}/")
        except Exception as e:
            logging.error(traceback.format_exc())
            zip_ref.close()
            return (False, package_meta)

        zip_ref.close()
        return (parsed_raw_dir_list, package_meta)

    elif package_meta["saved_file_name"].endswith(".tar.gz"):
        if verbose and not output_json:
            print(f"-> Extracting tarball: {package_meta['saved_file_name']}")
        tar_ref = tarfile.open(package_meta["saved_file_name"], "r")
        package_meta["archive_file_list"] = tar_ref.getnames()
        package_meta["total_package_files"] = len(package_meta["archive_file_list"])

        parsed_raw_dir_list = list(
            file for file in package_meta["archive_file_list"] if file.endswith(".py")
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
                f"{package_meta['saved_file_name']} found. Not a wheel or tarball, can't handle anything else yet."
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


def _clean_up_downloads(
    package_meta, output_dir, verbose=False, debug=False, output_json=False
):
    # Empty the files first
    for file in package_meta["archive_file_list"]:
        file_target = os.path.join(output_dir, file)
        if debug:
            print(f"Trying to delete: {file_target}")
        if os.path.isfile(file_target):
            try:
                os.remove(file_target)
            except Exception as e:
                logging.error(traceback.format_exc())

    # Remove the directories
    dirs = set(dirs.split("/")[0] for dirs in package_meta["archive_file_list"])
    for dir in dirs:
        directory = os.path.join(output_dir, dir)
        if os.path.isdir(directory):
            if debug:
                print(f"Trying to delete dir: {directory}")
            try:
                shutil.rmtree(directory)
            except Exception as e:
                logging.error(traceback.format_exc())

    # delete archive
    if debug:
        print(f"Trying to delete: {package_meta['saved_file_name']}")
    if os.path.isfile(package_meta["saved_file_name"]):
        try:
            os.remove(package_meta["saved_file_name"])
        except Exception as e:
            logging.error(traceback.format_exc())


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
@click.option(
    "-s",
    "--save_files",
    "save_files",
    help="CAUTION! Don't clean up the pip downloads and extracted archive files.  Careful, the whole PyPI archive has over 2 million files",
    is_flag=True,
)
def main(package_name, output_dir, verbose, debug, output_json, input_list, save_files):
    # Normalize targeting options
    targets = []
    if package_name:
        targets.append(package_name)
    elif input_list:
        targets = _decode_json_file(input_list)
    # else:
    # targets = _pull_from_queue()

    if verbose and not output_json:
        print("-> Loading scan plugins")
    scan_plugins = PluginManager()
    scan_plugins.setPluginPlaces(["plugins"])
    scan_plugins.collectPlugins()
    all_plugins = scan_plugins.getAllPlugins()

    # Fire!
    scan_errors = 0
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
                output=output,
                output_dir=output_dir,
                package_meta=package_meta,
                verbose=verbose,
                debug=debug,
                output_json=output_json,
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
                    output_json=output_json,
                )

                if scan_list and package_meta:
                    responses = []
                    for plugin in all_plugins:
                        responses.append(
                            plugin.plugin_object.scan(
                                scan_list, output_dir, package_meta, verbose, debug, output_json
                            )
                        )
                    scan_errors += sum(responses)
                    if debug:
                        pprint(responses)
                    # @TODO add package cleanup routine
                    # package_meta["saved_file_name"]
                    if not save_files and package_meta:
                        if verbose and not output_json:
                            print("-> Cleaning up downloaded files")
                        if debug:
                            pprint(package_meta)
                        _clean_up_downloads(
                            package_meta, output_dir, verbose, debug, output_json
                        )

        else:
            if verbose and not output_json:
                print(f"! Pip download failed for {raw_input}")
            scan_errors += 1
    if verbose and not output_json:
        print(f"Scan complete! {scan_errors} errors.")


if __name__ == "__main__":
    init()  # @TODO move this to inside main, assume this is not usually needed
    main()
