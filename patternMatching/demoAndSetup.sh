#!/bin/bash

echo "\nStarting this shell script with some checkups\n"

echo "Setting up the dumps if required\n"
if ! [ -f dump.txt ] || ! [ -f dump2.txt ];
then
  echo "The two dumps need to be created, that might take a while as they each should be around 100 MB\n"
  if [ -f dump.txt ];
  then
    rm dump.txt
  fi
  if [ -f dump2.txt ];
  then
    rm dump2.txt
  fi
  if [ -f dumpProducer.py ];
  then
    python3 dumpProducer.py
  else
    echo "You lack a file called dumpProducer.py\n"
    exit 100
  fi
else
  echo "The dumps seem correctly setup\n"
fi

echo "Setting up the blacklist if required\n"
if ! [ -f unifiedBlacklist ];
then
  echo "No blacklist found, looking for a solution\n"
  if [ -f unifiedBlacklist.zip ];
  then
    unzip unifiedBlacklist.zip
    echo "Blacklist retrieved from compressed archive\n"
  else
    echo "You are lacking a file called unifiedBlacklist, or its compressed self unifiedBlacklist.zip\n"
    exit 100
  fi
else
  echo "No action required for the blacklist\n"
fi

echo "Running the actual Python script\n"
if [ -f testAhocorasick.py ];
then
  python3 testAhocorasick.py
else
  echo "You lack a file called testAhocorasick.py (the most important one, as it contains the pattern matching script)\n"
  exit 100
fi
echo "Script over\n"
