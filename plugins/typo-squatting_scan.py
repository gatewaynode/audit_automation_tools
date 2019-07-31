import jellyfish  # Used to compute distance between two strings in terms of deletion, insertion, substitution and transposition.
import traceback
import requests
import logging
import json
import sys
import os
import re

from yapsy.IPlugin import IPlugin

plugin_location = os.path.dirname(
    sys.argv[0]
)  # The location of the directory where the plugin is located.


class Typo_Squatting_Protection(IPlugin):
    def scan(
        self,
        scan_list=[],
        package_meta={},
        output_dir="",
        verbose=False,
        debug=False,
        output_json=False,
    ):
        # Defining some smaller functions to help with the execution.

        def _downloading_top_5000():
            inventory_raw = requests.get(
                "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-365-days.json"
            )
            with open(
                f"{plugin_location}/top5000_list.json", "w", encoding="utf-8"
            ) as file:
                file.write(inventory_raw.text)

        def _loading_top_5000():
            if os.path.exists(f"{plugin_location}/top5000_list.json"):
                with open(
                    f"{plugin_location}/top5000_list.json", "r", encoding="utf-8"
                ) as file:
                    inventory_list = json.loads(
                        file.read()
                    )  # Reads all the file at once, can create problems
                    inventory = list(
                        project["project"] for project in inventory_list["rows"]
                    )
                    return inventory
            else:
                _downloading_top_5000()
                return _loading_top_5000()  # Recursive call because I am lazy.

        def _name_distance_indicator(pkg_name_1, pkg_name_2):
            if pkg_name_1 == pkg_name_2:
                return float(
                    "inf"
                )  # We don't want the scan to report that, for instance, numpy is a name very close to that of the popular package numpy...
            return (
                2
                * jellyfish.damerau_levenshtein_distance(pkg_name_1, pkg_name_2)
                / (len(pkg_name_1) + len(pkg_name_2))
            )

        scan_errors = 0

        threshold = 0.3
        try:
            top5000_list = _loading_top_5000()
        except Exception as e:
            logging.error(traceback.format_exc())
            scan_errors += 1

        pkg_names_list = []

        for pkg_dir in scan_list:

            ### First step is to find the registered name of the package on PyPi in the setup.py file.
            ### That step is really long and obscure, sorry about that, but we have to take every possible case into account.

            setup_location = None
            for root, dirs, files in os.walk(f"{output_dir}/{pkg_dir}"):
                if "setup.py" in files:
                    setup_location = os.path.join(root, "setup.py")

            if (
                not setup_location
            ):  # It is entirely possible to have no setup.py file in a package, in case that package has a METADATA file. Just to be sure we add the package root dir in the pkg_names_list in order to be sure that no package will go unnoticed.
                try:
                    raise Exception(
                        f"The setup.py file could not be found in {pkg_dir}, that may not be an issue if a METADATA file is found later on."
                    )
                except Exception as e:
                    logging.error(traceback.format_exc())
                pkg_name = pkg_dir  # a default name for the script to work with.

            if (
                setup_location
            ):  # in case where there are both a setup.py and a metadata file, the setup.py will be considered more reliable.

                ### In the absolutely unreadable bit of code that follows, we do twice the same thing:
                ### Step 1 : find all occurences of a call to the setup method.
                ### Step 2 : Count the number of occurences found. If there are more or less than one, raises the error counter.
                ### Step 3 : Do the same thing with all occurences with every occurence of "name=" in the arguments of the setup call.

                with open(setup_location, "r") as setup_file:
                    setup_file_content = (
                        setup_file.read()
                    )  # Reads all at once, poor RAM management but makes re easier to work with.

                    # all_setup_call_location = [(m.start(),m.end()) for m in re.finditer("setup\([^)]+\)",setup_file_content)]
                    all_setup_call_location = [
                        (m.start(), m.end())
                        for m in re.finditer("setup\([^)]+\)", setup_file_content)
                    ]
                    # Have I ever mentionned that I find regular expressions unreadable ?

                    if (
                        len(all_setup_call_location) > 1
                    ):  # there should only be one call, anything else seems suspicious
                        try:
                            raise Exception(
                                f"The setup.py file in {pkg_dir} contains more than one call of setup, which is suspicious and may lead to parsing mistakes from this script."
                            )
                        except Exception as e:
                            logging.error(traceback.format_exc())
                            scan_errors += 1

                        first_setup_call_location = all_setup_call_location[0]
                        setup_call_arguments = setup_file_content[
                            first_setup_call_location[0]
                            + 6 : first_setup_call_location[1]
                            - 1
                        ]  # the part of the line containing the arguments for the setup call.
                        all_namings = [
                            (m.start(), m.end())
                            for m in re.finditer(
                                "name=[^,)]+[,)]", setup_call_arguments
                            )
                        ]  # finds all occurences of what could be the naming of the package in the setup call file.

                        if (
                            len(all_namings) > 1
                        ):  # Same fight here, there should only be one occurence of name=
                            try:
                                raise Exception(
                                    f"The setup call in the setup.py file in {pkg_dir} seems to give several names to its package, which is suspicious and may lead to parsing mistakes from this script."
                                )
                            except Exception as e:
                                logging.error(traceback.format_exc())
                                scan_errors += 1
                            first_naming_call = all_namings[0]
                            pkg_name = (
                                setup_call_arguments[
                                    first_naming_call[0] + 5 : first_naming_call[1] - 1
                                ]
                                .strip("'")
                                .strip('"')
                            )  # remove the quotes in the original python code.

                        elif len(all_namings) == 0:
                            try:
                                raise Exception(
                                    f"The setup call in the setup.py file in {pkg_dir} doesn't seem to contain the name of the package, which is suspicious and may lead to parsing mistakes from this script."
                                )
                            except Exception as e:
                                logging.error(traceback.format_exc())
                                scan_errors += 1
                            pkg_name = pkg_dir

                        else:
                            first_naming_call = all_namings[0]
                            pkg_name = (
                                setup_call_arguments[
                                    first_naming_call[0] + 5 : first_naming_call[1] - 1
                                ]
                                .strip("'")
                                .strip('"')
                            )  # remove the quotes in the original python code.

                    elif len(all_setup_call_location) == 0:
                        try:
                            raise Exception(
                                f"The setup.py file in {pkg_dir} doesn't contain any call of setup, which is suspicious and may lead to parsing mistakes from this script."
                            )
                        except Exception as e:
                            logging.error(traceback.format_exc())
                            scan_errors += 1
                        pkg_name = (
                            pkg_dir
                        )  # defaults to the name of the root directory of the package.

                    else:
                        first_setup_call_location = all_setup_call_location[0]
                        setup_call_arguments = setup_file_content[
                            first_setup_call_location[0]
                            + 6 : first_setup_call_location[1]
                            - 1
                        ]  # the part of the line containing the arguments for the setup call.
                        all_namings = [
                            (m.start(), m.end())
                            for m in re.finditer(
                                "name=[^,)]+[,)]", setup_call_arguments
                            )
                        ]  # finds all occurences of what could be the naming of the package in the setup call file.

                        if (
                            len(all_namings) > 1
                        ):  # Same fight here, there should only be one occurence of name=
                            try:
                                raise Exception(
                                    f"The setup call in the setup.py file in {pkg_dir} seems to give several names to its package, which is suspicious and may lead to parsing mistakes from this script."
                                )
                            except Exception as e:
                                logging.error(traceback.format_exc())
                                scan_errors += 1
                            first_naming_call = all_namings[0]
                            pkg_name = (
                                setup_call_arguments[
                                    first_naming_call[0] + 5 : first_naming_call[1] - 1
                                ]
                                .strip("'")
                                .strip('"')
                            )  # remove the quotes in the original python code.

                        elif len(all_namings) == 0:
                            try:
                                raise Exception(
                                    f"The setup call in the setup.py file in {pkg_dir} doesn't seem to contain the name of the package, which is suspicious and may lead to parsing mistakes from this script."
                                )
                            except Exception as e:
                                logging.error(traceback.format_exc())
                                scan_errors += 1
                            pkg_name = pkg_dir
                        else:
                            first_naming_call = all_namings[0]
                            pkg_name = (
                                setup_call_arguments[
                                    first_naming_call[0] + 5 : first_naming_call[1] - 1
                                ]
                                .strip("'")
                                .strip('"')
                            )  # remove the quotes in the original python code.

                if (
                    not pkg_name in pkg_names_list
                ):  # i.e. if we haven't already registered the name (which should never happend, but is added with the scan in metadata)
                    pkg_names_list.append(
                        pkg_name
                    )  # all packages appear at least once in the scan_list, so we are certain that each package will at least appear once in this list.

        ### Here we do basically the same work once more with the informations obtained from METADATA files.
        all_metadata_paths = []

        archive_file_list = package_meta["archive_file_list"]
        for filepath in archive_file_list:
            if filepath.endswith("METADATA") or filepath.endswith(
                "PKG-INFO"
            ):  # Both files contain the package name
                all_metadata_paths.append(filepath)

        for metadata_path in all_metadata_paths:
            with open(f"{output_dir}/{metadata_path}", "r") as metadata_file:
                metadata_line = metadata_file.readline().rstrip()
                metadata_name_found = (
                    False
                )  # indicates whether the name of the package was found in metadata. If not, it seems suspicious.
                while metadata_line:
                    if metadata_line.startswith("Name: "):

                        pkg_name = metadata_line[
                            6:
                        ]  # the rest of the line is considered to be the package name.
                        if not pkg_name in pkg_names_list:
                            pkg_names_list.append(pkg_name)

                        metadata_name_found = True
                        break  # just for efficiency
                    metadata_line = metadata_file.readline().rstrip()

                if not metadata_name_found:
                    try:
                        raise Exception(
                            f"The METADATA file at {metadata_path} doesn't seem to contain the name of the package, which is suspicious and may lead to parsing mistakes from this script."
                        )
                    except Exception as e:
                        logging.error(traceback.format_exc())
                        scan_errors += 1

        ############# Once that point has been reached the script should have found a pkg_name to work with.

        for pkg_name in pkg_names_list:

            if verbose and not output_json:
                print(
                    f"-> Running typo-squatting detection against package {pkg_name}. Output saved to {output_dir}."
                )

            with open(
                f"{output_dir}/typo_squatting_{pkg_name}.txt", "w", encoding="utf-8"
            ) as scan_results:
                try:
                    suscpicion_list = []
                    suscpicion_count = 0
                    for top_pkg in top5000_list:
                        if _name_distance_indicator(pkg_name, top_pkg) < threshold:
                            suscpicion_list.append(top_pkg)
                            suscpicion_count += 1
                    scan_results.write(
                        f"{pkg_name}- Potential typo squattings detected -{suscpicion_count}- List of potentially typo squatted packages -{suscpicion_list}\n"
                    )  # The - are here to make the output easier to parse later on.
                except Exception as e:
                    logging.error(traceback.format_exc())
                    scan_errors += 1

        return scan_errors
