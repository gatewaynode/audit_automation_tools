Audit Tools
===========
Some simple tooling to help automate a security audit for pip and PyPI.  Right now this just contains a wrapper called pip_audit that uses pip to download a non-binary version of a package, crack open the wheel and run Bandit and Detect Secrets against it.  The resulting reports (along with the source and wheel) are stored in a local_files directory inside this codebase.

This is very rudimentary, just barely hits MVP, has no tests and expects you to have some idea of how to install it.

The task runner is Python Invoke instead of the Makefile I usually provide.

The code formatter is Black.

The Python version is Python 3.7.3

Built and "tested" on Linux, KDE Neon latest stable

Usage
-----

Audit a single package:
```bash
./pip_audit.py -v -p urllib3
```

Audit a JSON list of packages:
```bash
./pip_audit -v -i my_list.json
```

You can also download the entire list of PyPI packages with the invoke task:
```bash
invoke megaupdate
```

Input is handled with Click so there is some basic help as well.
```bash
./pip_audit.py --help
```

Install
-------
Install Python Invoke and invoke the virtualenv build (you might need to install python-invoke first).
```bash
invoke virtualenv
source env/bin/activate
```

As always, please fork away, open issues and such.
