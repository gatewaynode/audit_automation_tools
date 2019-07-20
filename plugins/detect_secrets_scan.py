import subprocess
import logging
import traceback
from yapsy.IPlugin import IPlugin


class Detect_Secrets_Scanner(IPlugin):
    def scan(
        self, scan_list=[], output_dir="", verbose=False, debug=False, output_json=False
    ):
        scan_errors = 0
        if scan_list:
            if verbose and not output_json:
                print(
                    f"-> Running detect-secrets against package dirs {', '.join(scan_list)}.  Output saved to {output_dir}."
                )
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
        else:
            scan_errors += 1

        return scan_errors
