import ahocorasick  # The core of the script, enable to look for several substrings in a string simultaneously
import psutil  # Used to monitor RAM usage and avoid troubles with RAM saturation.
import pickle  # Used to serialize the automaton for the Aho-Corasick algorithm.
import os  # Used for general file manipulation.


def stringMatching(toLookFor, textFilePathList, precompiledPath=None, verbose=False):
    "Uses the Aho-Corasick algorithm to match multiple strings at once in a text.\nImportant : if a file is found at the precompiledPath, the script will ignore the values passed in toLookFor."
    # The script uses the Aho-Corasick algorithmn, which is also used by fgrep (source Wikipedia)

    if not precompiledPath is None and os.path.exists(
        precompiledPath
    ):  # cf later on, we can reuse the automaton for a given blacklist if we have already compiled it once.
        if verbose:
            print(
                "Loading existing automaton for accelerated reasearch"
            )  # depending on the availlable amount of RAM of the system, this recycling approach might not be faster than simple recompilation.
        ahocorasick_automaton = pickle.load(open(precompiledPath, "rb"))

    else:
        ahocorasick_automaton = (
            ahocorasick.Automaton()
        )  # The class provided to make use of the aho-corasick algorithm.

        if verbose:
            print("Compiling new automaton for accelerated reasearch")
        for word in toLookFor:  # Adding the keys that we will be looking for.
            ahocorasick_automaton.add_word(
                word.lower(), word
            )  # first value = what to look for, second value = what to return when first value is found.

        # If toLookFor is really huge that step can last for a short while.
        ahocorasick_automaton.make_automaton()  # creating the automaton for accelerated search.

        if not precompiledPath is None:
            # Important note : if the blacklist isn't changed, the automaton only needs to be computed once and can be re-used.
            pickle.dump(
                ahocorasick_automaton,
                open(precompiledPath, "wb"),
                protocol=pickle.HIGHEST_PROTOCOL,
            )
            # The automaton can be really huge, ~522 MB according to my filesystem when used on the ~26 MB blacklist.

    matchFounds = list()
    for textFilePath in textFilePathList:
        if verbose:
            print("\nScanning file : " + textFilePath + "\n")
        with open(
            textFilePath, "r", encoding="utf-8"
        ) as textFile:  # I assume utf-8, because why not?
            # one problem is that we have to put the whole string in memory in order to use the aho-corasick algorithm.
            # in order to avoid any troubles with that I will only try to load what the RAM seems able to handle.
            availableRAM = psutil.virtual_memory()[
                1
            ]  # the amount of available bytes in RAM according to the system.
            fileSize = os.path.getsize(
                textFilePath
            )  # the file size according to the system.
            if (
                3 * fileSize < 2 * availableRAM
            ):  # i.e. if we can fit the file in RAM without filling more than two-third of it (in order to keep some margin).
                if verbose:
                    print(f"Enough RAM to test the whole file {textFilePath} in one pass")
                for end_index, value in ahocorasick_automaton.iter(
                    textFile.read().lower()
                ):  # string comparisons are case sensitive, so both the keywords and the selected text are cast to lowercase.
                    # value correspond to the second value that we passed to A before.
                    start_index = end_index - len(value) + 1
                    matchFounds.append((textFilePath, start_index, value))
                    if verbose:
                        print(textFilePath + " : " + value + " : " + str(start_index))
            else:
                if verbose:
                    print(f"Not enough RAM to test the whole file {textFilePath} in one pass")
                # Here I will assume that each utf-8 character is encoded in 4 bits, which is a worst-case scenario (they should mostly be encoded on 1 bit).
                pointerPosition = (
                    textFile.tell()
                )  # since we have to look for the EOF character we will have to move in the file in order not to loose any character.
                while textFile.read(1):  # will return -1 if end of file and pass else
                    textFile.seek(
                        pointerPosition
                    )  # we move back the pointer in order to read the character used in the test once more.
                    availableCharSpace = (
                        psutil.virtual_memory()[1] // 6
                    )  # (almost) The theorical amount of 4-bits characters we could fit in 2/3 of the RAM, in order to keep some margins. I recompute the value of the availableRAM because it could have changed over time.
                    for end_index, value in ahocorasick_automaton.iter(
                        textFile.read(availableCharSpace).lower()
                    ):  # string comparisons are case sensitive, so both the keywords and the selected text are cast to lowercase.
                        # Once we reach end of file no other characters should be read, so asking for too much characters shouldn't be an issue.
                        start_index = (
                            end_index - len(value) + 1
                        )  # Not usable on its own when reading the file in multiple parts, because the algorithm returns the position among the given text without adding an offset because of the previous parts (which makes sense).
                        matchFounds.append(
                            (textFilePath, pointerPosition + start_index, value)
                        )  # The pointerPosition enables to get the absolute position of the matches in the file.
                        if verbose:
                            print(
                                textFilePath
                                + " : "
                                + value
                                + " : "
                                + str(pointerPosition + start_index)
                            )
                    pointerPosition = (
                        textFile.tell()
                    )  # set new pointer position or we will keep reading the same characters over and over.
    return matchFounds
