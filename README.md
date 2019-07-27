Audit Tools
===========
Some simple tooling to help automate a security audit for pip and PyPI.  Right now this just contains a wrapper called pip_audit.py that uses pip to download a non-binary version of a package, crack open the archive and run the plugins against it.  The resulting reports (along with the source and wheel) are stored in a local_files directory inside this codebase.  By default there is no stdout, this is meant to be run in an automation orchestation.  But if you are just trying it out on the CLI the verbose flag, `-v`, must be supplies to see what it is doing.

The scanners, currently just Bandit and Detect Secrets, are run as plugins(YAPSY) in the plugin directory.  More are planned.

**Currently Pre 0.1 release.  No API's are stable!**

The task runner is Python Invoke instead of the Makefile I usually provide.

The code formatter is Black (if contributing run this before requesting a pull).

Testing framework is PyTest.

The Python version is Python 3.7.3

Built and "tested" on Linux, KDE Neon latest stable.

Usage
-----
```
Usage: pip_audit.py [OPTIONS]

Options:
  -p, --package TEXT  The PyPI package to audit
  -o, --output TEXT   The directory to unarchive into.
  -v, --verbose       Show more information.
  -d, --debug         Internal data information.
  -j, --json          Run scanners with JSON output.  Disables verbose.
  -i, --input TEXT    Input list file, in json format, of packages to scan.
  -s, --save_files    CAUTION! Don't clean up the pip downloads and extracted archive files.  Careful, the whole PyPI archive has over 2 million files
  --help              Show this message and exit.
```

Audit a single package:
```bash
./pip_audit.py -v -p urllib3
```
You'll get some files in a directory off the source code root call local_files, these are the reports from the various plugins.

Audit a JSON list of packages:
```bash
./pip_audit -v -i my_list.json
```

You can also download the entire list of PyPI packages with the invoke task:
```bash
invoke megaupdate
```

Or download a more reasonably sized top 5000 list of PyPI packages:
```bash
invoke top5000
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

Contributing
------------
As always, please fork away, merge requests are welcome, open issues and such.  There is a discussion board at https://www.reddit.com/r/pipsecurity/

The best way to contribute is by providing additional plugins in the plugins directory, by default all plugins will be run against the files in the archive that `pip` downloads.  This is subject to change as there will be a way to control which plugins are run in the near future.

Roadmap
-------
* Summary reports of plugins that support them
* Automatic reporting of summaries to Github projects
* PyLint plugin
* ElasticSearch results storage mode
* CLI integration
* Plugin execution control
