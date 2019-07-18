import ahocorasick      # The core of the script, enable to look for several substrings in a string simultaneously
import psutil           # Used to monitor RAM usage and avoid troubles with RAM saturation.
import pickle           # Used to serialize the automaton for the Aho-Corasick algorithm.
import os               # Used for general file manipulation.

def stringMatching(toLookFor,textFilePathList):
    # The script uses the Aho-Corasick algorithmn, which is also used by fgrep (source Wikipedia)

    # !!! Important : If the toLookFor list is changed but the automaton has already been compiled, the file "precompiledAutomaton" must be deleted or the script will assume that nothing needs to be changed.

    if os.path.exists("precompiledAutomaton"):  #cf later on, we can reuse the automaton for a given blacklist if we have already compiled it once.
        print("Loading existing automaton")     # depending on the availlable amount of RAM of the system, this recycling approach might not be faster than simple recompilation.
        ahocorasick_automaton = pickle.load(open("precompiledAutomaton","rb"))

    else:
        ahocorasick_automaton = ahocorasick.Automaton() # The class provided to make use of the aho-corasick algorithm.

        print("Registering every word from blacklist")
        for word in toLookFor:  # Adding the keys that we will be looking for.
            ahocorasick_automaton.add_word(word,word)   # first value = what to look for, second value = what to return when first value is found.

        print("Creating automaton") # If toLookFor is really huge that step can last for a short while.
        ahocorasick_automaton.make_automaton()  # creating the automaton for accelerated search.

        # Important note : if the blacklist isn't changed, the automaton only needs to be computed once and can be re-used.
        print("Serialising automaton")
        pickle.dump(ahocorasick_automaton,open("precompiledAutomaton","wb"), protocol=pickle.HIGHEST_PROTOCOL)
        # The automaton is really huge, ~522 MB according to my filesystem.

    for textFilePath in textFilePathList:
        print("\nScanning file : " + textFilePath + "\n")
        with open(textFilePath,"r",encoding="utf-8") as textFile: # I assume utf-8, because why not?
                # one problem is that we have to put the whole string in memory in order to use the aho-corasick algorithm.
                # in order to avoid any troubles with that I will only try to load what the RAM seems able to handle.
                availableRAM = psutil.virtual_memory()[1]   # the amount of available bytes in RAM according to the system.
                fileSize = os.path.getsize(textFilePath) # the file size according to the system.
                if 3*fileSize < 2*availableRAM: #i.e. if we can fit the file in RAM without filling more than two-third of it (in order to keep some margin).
                    print("Enough RAM to test the whole file in one pass")
                    for end_index, value in ahocorasick_automaton.iter(textFile.read()):    # value correspond to the second value that we passed to A before.
                        start_index = end_index - len(value) + 1
                        print(textFilePath + " : " + value + " : " + str(start_index))
                else:
                    print("Not enough RAM to test the whole file in one pass")
                    # Here I will assume that each utf-8 character is encoded in 4 bits, which is a worst-case scenario (they should mostly be encoded on 1 bit).
                    pointerPosition = textFile.tell()   # since we have to look for the EOF character we will have to move in the file in order not to loose any character.
                    while textFile.read(1):     # will return -1 if end of file and pass else
                        textFile.seek(pointerPosition)      # we move back the pointer in order to read the character used in the test once more.
                        availableCharSpace = psutil.virtual_memory()[1]//6    # (almost) The theorical amount of 4-bits characters we could fit in 2/3 of the RAM, in order to keep some margins. I recompute the value of the availableRAM because it could have changed over time.
                        print("AvailableCharSpace for this pass : " + str(availableCharSpace))
                        for end_index, value in ahocorasick_automaton.iter(textFile.read(availableCharSpace)):    # Once we reach end of file no other characters should be read, so asking for too much characters shouldn't be an issue.
                            start_index = end_index - len(value) + 1    # Not reliable when reading the file in multiple parts, because the algorithm returns the position amoung the given text without adding an offset because of the previous parts (which makes sense).
                            print(textFilePath + " : " + value + " : " + str(start_index))
                        pointerPosition = textFile.tell()   # set new pointer position or we will keep reading the same characters over and over.

# A small part of the code to test the script on the two produced dump files against the provided blacklist.

blackList = []          # Source de la blacklist : http://www.shallalist.de/
with open("unifiedBlacklist","r",encoding="utf-8") as unifiedBlacklist:
    line = unifiedBlacklist.readline()
    while line:
        blackList.append(line)
        line = unifiedBlacklist.readline()

# toLookForExample = ["dog","fence","car","convolution"] # A list of strings to be searched for simultaneously in the file.
textFilePathExample = ["dump.txt","dump2.txt"]      # A list of files to scan for the interessting strings.
stringMatching(blackList,textFilePathExample)
