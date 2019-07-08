from invoke import task
from invoke import run

@task
def virtualenv():
    run("virtualenv --prompt '>- pip audit -< ' --python=python3.7 env")
    run("env/bin/pip install -r requirements.txt")
    run("echo")
    run("echo 'VirtualENV Setup Complete.  Now run: source env/bin/activate'")
    run("echo")
