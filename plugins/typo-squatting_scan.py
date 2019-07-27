import jellyfish  # Used to compute distance between two strings in terms of deletion, insertion, substitution and transposition.
import traceback
import requests
import logging
import json
import sys
import os

from yapsy.IPlugin import IPlugin

plugin_location = os.path.dirname(
    sys.argv[0]
)  # The location of the directory where the plugin is located.


class Typo_Squatting_Protection(IPlugin):
    def scan(
        self, scan_list=[], output_dir="", verbose=False, debug=False, output_json=False
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

        for pkg_name in scan_list:
            with open(
                f"{output_dir}/typo_squatting_{pkg_name}.txt", "w", encoding="utf-8"
            ) as scan_results:
                if verbose and not output_json:
                    print(
                        f"-> Running typo-squatting detection against package {pkg_name}. Output saved to {output_dir}."
                    )
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
