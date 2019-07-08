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

```bash
./pip_audit.py -v -p urllib3
```
Literally this is the only package I've tested it with.  Undoubtedly there will be some packages that will break it.

Input is handled with Click so there is some basic help as well.
```bash
./pip_audit.py --help
```

Install
-------
Install Python Invoke and invoke the virtualenv build.
```bash
invoke virtualenv
source env/bin/activate
```

As always, please fork away, open issues and such.
