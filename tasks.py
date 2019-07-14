from invoke import task
from invoke import run

@task
def virtualenv():
    run("virtualenv --prompt '>- pip audit -< ' --python=python3.7 env")
    run("env/bin/pip install -r requirements.txt")
    run("echo")
    run("echo 'VirtualENV Setup Complete.  Now run: source env/bin/activate'")
    run("echo")


@task
def clean():
    run("mv -v local_files/simple_list.json ../")
    run("rm -rvf local_files/*")
    run("mv -v simple_list.json local_files/")
