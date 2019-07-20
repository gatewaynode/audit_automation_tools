from invoke import task
from invoke import run
import requests
import json
import traceback
import logging
import sys
from pprint import pprint


@task
def virtualenv():
    run("virtualenv --prompt '>- pip audit -< ' --python=python3.7 env")
    run("env/bin/pip install -r requirements.txt")
    run("echo")
    run("echo 'VirtualENV Setup Complete.  Now run: source env/bin/activate'")
    run("echo")


@task
def clean():
    run("rm -rvf local_files/*")
    run("rm -rvf plugins/__pycache__")


@task
def megaupdate():
    try:
        inventory_raw = requests.get("https://pypi.org/simple/")
    except Exception as e:
        logging.error(traceback.format_exc())
        sys.exit(1)
    inventory_list = inventory_raw.text.split("\n")[6:-2]
    inventory = []
    for line in inventory_list:
        inventory.append(line.strip().split("\">")[1].replace("</a>", ""))
    with open("mega_list.json", "w", encoding="utf-8") as file:
        json.dump(inventory, file, ensure_ascii=False, indent=4)
        

@task
def top5000():
    try:
        inventory_raw = requests.get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-365-days.json")
    except Exception as e:
        logging.error(traceback.format_exc())
    inventory_list = json.loads(inventory_raw.text)
    #inventory = []
    inventory = list(project["project"] for project in inventory_list["rows"])
    with open("top5000_list.json", "w", encoding="utf-8") as file:
        json.dump(inventory, file, ensure_ascii=False, indent=4)
