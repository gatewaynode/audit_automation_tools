import ast
import distance
import logging
import traceback
import pickle
import sys
import os
from apted import APTED, PerEditOperationConfig
from yapsy.IPlugin import IPlugin

root_folder = os.path.dirname(
    os.path.abspath(sys.argv[0])
)  # The location of the script that this plugin is imported from, hence assuming that it is being called from pip_audit the folder is the root folder of the project.
plugin_location = os.path.join(root_folder, "plugins/")
resources_location = os.path.join(root_folder, "resources/")

sys.path.append(
    resources_location
)  # used to import custom libraries and easily access other resources.
from ast_parsing_resources_pkg import levenshtein_free_deletion, Node


class Ast_scan(IPlugin):
    def scan(
        self,
        scan_list=[],
        package_meta={},
        output_dir="",
        verbose=False,
        debug=False,
        output_json=False,
        **kwargs,
    ):
        def _recursive_node_tree(node):
            native_children = ast.iter_child_nodes(node)
            node_children = [
                _recursive_node_tree(native_child) for native_child in native_children
            ]
            node_name = str(type(node).__name__)
            return Node(node_name, node_children)

        def _create_node_tree(ast_tree):
            native_children = ast_tree.body
            node_children = [
                _recursive_node_tree(native_child) for native_child in native_children
            ]
            node_name = "root"
            return Node(node_name, node_children)

        def _deep_first_search(created_tree):
            deep_first_result = []
            search_stack = [created_tree]  # Not really a stack, but whatever.
            while (
                search_stack
            ):  # i.e. if not len(search_stack)==0: that syntax is the PEP 8 recommendation...
                node = (
                    search_stack.pop()
                )  # we are looking at a tree, so no need to check if we have already visited the node (it is impossible)
                deep_first_result.append(node.name)
                for child in node.children:
                    search_stack.append(child)
            return deep_first_result

        def _load_forbidden_patterns():
            if os.path.exists(os.path.join(resources_location, "forbidden_patterns")):
                with open(
                    os.path.join(resources_location, "forbidden_patterns"), "rb"
                ) as forbidden_patterns_file:
                    forbidden_patterns_tuple = pickle.load(forbidden_patterns_file)
                return forbidden_patterns_tuple[0], forbidden_patterns_tuple[1]
            else:  # No blacklist found, will raise an error.
                with open(
                    os.path.join(output_dir, "ast_scan_warnings.txt"), "w"
                ) as warning_file:
                    warning_file.write(
                        "The pattern blacklist is missing, the pattern scan will be skipped."
                    )
                return [], []

        scan_errors = 0

        forbidden_patterns_tree, forbidden_patterns_deep_first = (
            _load_forbidden_patterns()
        )
        forbidden_length = len(
            forbidden_patterns_tree
        )  # for for loops, also the length of forbidden_patterns_deep_first
        threshold = 2  # arbitrary value, should be tuned later on.

        if scan_list:
            if verbose and not output_json:
                print(
                    f"-> Running ast_scan against files {', '.join(scan_list)}. Output saved to {output_dir}."
                )

            try:
                for scanned_package in scan_list:
                    with open(
                        os.path.join(
                            output_dir,
                            f"ast_scan_{os.path.basename(scanned_package)}.txt",
                        ),
                        "w",
                        encoding="utf-8",
                    ) as output_file:

                        walked_package = os.walk(
                            os.path.join(output_dir, scanned_package)
                        )
                        all_target_files = (
                            []
                        )  # Not keeping track of directories, because why would we ...
                        for (root, dirs, files) in walked_package:
                            for file_name in files:
                                all_target_files.append(os.path.join(root, file_name))

                        print(os.path.join(output_dir, scanned_package))

                        for target in all_target_files:
                            with open(target, "r") as target_file:
                                try:
                                    ast_tree = ast.parse(target_file.read())
                                    node_tree = _create_node_tree(ast_tree)
                                    deep_first_tree = _deep_first_search(
                                        node_tree
                                    )  # used for faster approximated comparison

                                    for i in range(forbidden_length):
                                        deep_first_forbidden = forbidden_patterns_deep_first[
                                            i
                                        ]
                                        if (
                                            levenshtein_free_deletion(
                                                deep_first_forbidden, deep_first_tree
                                            )
                                            < threshold
                                        ):  # if the fast approximation hints at something...
                                            tree_forbidden = forbidden_patterns_tree[i]
                                            tree_apted_inclusion = APTED(
                                                tree_forbidden,
                                                node_tree,
                                                PerEditOperationConfig(1, 0, 1),
                                            )
                                            if (
                                                tree_apted_inclusion.compute_edit_distance()
                                                < threshold
                                            ):
                                                output_file.write(
                                                    f"The forbidden pattern n°{i} was detected in the file {target}\n"
                                                )
                                # The selected file may very well not be a python script.
                                except UnicodeDecodeError:
                                    with open(
                                        os.path.join(
                                            output_dir, "ast_scan_warnings.txt"
                                        ),
                                        "a",
                                    ) as warning_file:
                                        warning_file.write(
                                            f"An error happened while decoding the file {target}. It may not even be a text file, and thus not a python script.\n"
                                        )
                                except SyntaxError:
                                    with open(
                                        os.path.join(
                                            output_dir, "ast_scan_warnings.txt"
                                        ),
                                        "a",
                                    ) as warning_file:
                                        warning_file.write(
                                            f"An error happened while parsing the file {target}. It is a valid text file, but doesn't seem like a python script.\n"
                                        )

            except Exception as e:
                logging.error(traceback.format_exc())
                scan_errors += 1

        return scan_errors
