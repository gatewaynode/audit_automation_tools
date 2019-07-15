from invoke import task
from invoke import run
import requests
import json

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
    

@task
def megaupdate():
    inventory_raw = requests.get("https://pypi.org/simple/")
    inventory_list = inventory_raw.text.split("\n")[6:-2]
    inventory = []
    for line in inventory_list:
        inventory.append(line.strip().split('">')[1].replace("</a>", ""))
    print(len(inventory))
    
