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

# Requiered to import patternMatching or any other script within ressources.
sys.path.insert(
    0, f"{os.path.dirname(sys.argv[0])}/ressources"
)  # Adds the folder with ressources for patternMatching to the path.
from patternMatching import stringMatching


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
        return (False, package_meta)
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


def _look_for_malicious_domains(
    scan_list, output_dir, verbose=False, debug=False, output_json=False
):  # I don't have any special treatment for debug and cannot yet output a json file.

    script_location = os.path.dirname(
        sys.argv[0]
    )  # Required to access scripts and files located in ressources

    scan_errors = 0
    for target in scan_list:
        try:
            # First, we create a list of all the files in the package.
            all_files_in_package = []
            for (dirpath, dirnames, filenames) in os.walk(
                os.path.join(output_dir, target)
            ):
                for filename in filenames:
                    all_files_in_package.append(os.path.join(dirpath, filename))

            # Then, we gather the list of blacklisted domains, unless it has already been compiled in the past, in which case we skip this part.
            blacklist = None
            if not os.path.exists(
                f"{script_location}/ressources/precompiled_blacklist_automaton"
            ):
                blacklist = []
                with open(
                    f"{script_location}/ressources/unifiedBlacklist.txt",
                    "r",
                    encoding="utf-8",
                ) as unified_blacklist:
                    line = unified_blacklist.readline()
                    while line:  # We read all the lines until we reach the end of file.
                        blacklist.append(
                            line.rstrip()
                        )  # rstrip removes trailling whitespaces and newline characters from strings (those would later on be a problem for the detection)
                        line = unified_blacklist.readline()
            string_matching_output = stringMatching(
                blacklist,
                all_files_in_package,
                precompiledPath=f"{script_location}/ressources/precompiled_blacklist_automaton",
            )
        except Exception as e:
            logging.error(traceback.format_exc())
            scan_errors += 1

        if debug:
            print("Trying to write to:")
            pprint(f"{output_dir}/malicious_domains_lookup_{target}.txt")
        try:
            file = open(f"{output_dir}/malicious_domains_lookup_{target}.txt", "w")
            for (text_file_path, start_index, domain) in string_matching_output:
                file.write(
                    f"In file {text_file_path}, at index {start_index} found the malicious domain {domain};\n"
                )
            file.close()
        except Exception as e:
            logging.error(traceback.format_exc())
            scan_errors += 1

    return scan_errors


def _try_setting_malicious_domain_lookup(verbose=False, debug=False, output_json=False):
    "Needed to make sure that the installation is ready to search for blacklisted domains in tested packages"

    script_location = os.path.dirname(
        sys.argv[0]
    )  # Needed to access the resources folder folder, which contains among other things the lacklist for malicious domains and the pattern matching script

    is_pattern_matching_correctly_setup = (
        True
    )  # Assuming that everything will work unless an ovious problem show up.
    # Several verifications to see whether the script will be able to start the malicious_domains_lookup later on. could be moved in its own method.
    if not os.path.exists(f"{script_location}/ressources/unifiedBlacklist.txt"):
        if verbose and not output_json:
            print(
                "The malicious domains blacklist was not found, the script will try to create it from the local archive"
            )
        try:
            zipped_blacklist = zipfile.ZipFile(
                f"{script_location}/ressources/unifiedBlacklist.zip", "r"
            )
        except FileNotFoundError:
            is_pattern_matching_correctly_setup = False
            raise RuntimeWarning(
                "You lack a file called unifiedBlacklist.zip in the folder ressources.\nIt countains a list of malicious URL to look for in scanned packages.\nOther functionalities are still available."
            )
        if (
            is_pattern_matching_correctly_setup
        ):  # The script will not try to decompress the archive if said archive is nowhere to be found in the first place.
            try:
                zipped_blacklist.extractall(f"{script_location}/ressources/")
            except Exception as e:
                logging.error(traceback.format_exc())
                zipped_blacklist.close()
                is_pattern_matching_correctly_setup = False
                raise RuntimeWarning(
                    "Could not decompress the archived blacklist.\nIt may have gotten corrupted, or something unpredicted might have happened.\nOther functionalities are still available."
                )
    if is_pattern_matching_correctly_setup:
        is_pattern_matching_correctly_setup = os.path.exists(
            f"{script_location}/ressources/patternMatching.py"
        )  # i.e. the setup is correct only if no previous steps have failed and the library exists.

    return is_pattern_matching_correctly_setup


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

    is_pattern_matching_correctly_setup = _try_setting_malicious_domain_lookup(
        verbose, debug, output_json
    )

    # Fire!
    for raw_input in targets:
        scan_list = []
        package_meta = {}
        scan_errors = 0

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
                    if verbose and not output_json:
                        print(
                            f"--> Running bandit against files {', '.join(scan_list)}. Output saved to {output_dir}."
                        )
                    if debug:
                        pprint(scan_list)
                    bandit_scan_results = _bandit_scan(
                        scan_list=scan_list,
                        output_dir=output_dir,
                        output_json=output_json,
                    )

                    if verbose and not output_json:
                        print(
                            f"--> Running detect-secrets against package dirs {', '.join(scan_list)}.  Output saved to {output_dir}."
                        )
                    if debug:
                        pprint(scan_list)
                    detect_secrets_scan_results = _detect_secrets_scan(
                        scan_list=scan_list,
                        output_dir=output_dir,
                        output_json=output_json,
                    )

                    if is_pattern_matching_correctly_setup:
                        if verbose and not output_json:
                            print(
                                f"--> Running blacklisted domains search against package dirs {', '.join(scan_list)}.  Output saved to {output_dir}."
                            )
                        if debug:
                            pprint(scan_list)
                        malicious_domains_lookup__result = _look_for_malicious_domains(
                            scan_list=scan_list,
                            output_dir=output_dir,
                            output_json=output_json,
                        )
                    elif verbose and not output_json:
                        print(
                            "Malicious domains lookup was skipped because it couldn't be correctly setup in the first place."
                        )
        else:
            if verbose and not output_json:
                print(f"! Pip download failed for {raw_input}")
            scan_errors += 1


if __name__ == "__main__":
    init()  # @TODO move this to inside main, assume this is not usually needed
    main()
