import string
import random
import os

# Script dedicated to producing huge text files to test the pattern finding algorithm on.
# The obtained dump files weigh around 100 MB.

print("Producing first dump")
with open("dump.txt","a") as dumpFile:
    for i in range(10000):
        dumpFile.write(''.join(random.choices(string.ascii_lowercase, k=10000)))
        dumpFile.write('\n')

print("Producing second dump")
with open("dump2.txt","a") as dumpFile:
    for i in range(10000):
        dumpFile.write(''.join(random.choices(string.ascii_lowercase, k=10000)))
        dumpFile.write('\n')
