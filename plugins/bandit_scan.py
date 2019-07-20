import subprocess
import logging
import traceback
from yapsy.IPlugin import IPlugin

class Bsndit_Scanner(IPlugin):
    def scan(
            self,
            scan_list=[],
            output_dir="",
            verbose=False, 
            debug=False, 
            output_json=False
        ):
        scan_errors = 0
        if scan_list:
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
        else:
            scan_errors += 1

        return scan_errors
