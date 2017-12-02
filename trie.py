# #######################
# Project: antispam
# Author: Martin Kopec
# #######################

import pygtrie as trie


class Trie:
    """
    Trie class creates a trie structure and implements operations over it
    """

    def __init__(self):
        self.tree = trie.Trie()

    def init(self, words):
        """Fills the trie structure by data.

        words - list of words/phrases to be put to the trie structure.
        """
        for w in words:
            for i in range(len(w)):
                # If saving path of the last character of the word
                # store True, False otherwise.
                # The structure will return False if a path (word)
                # is just a prefix of a banned word/phrase.
                last_char = i == len(w) - 1
                self.tree[w[:i + 1]] = last_char

    def banned_word_prefix(self, prefix):
        """
        Returns True if the prefix is a prefix of a banned word/phrase,
        otherwise returns False.

        prefix - string
        """
        try:
            self.tree[prefix]
            return True
        except KeyError:
            return False

    def is_banned_word(self, word):
        """Returns True if the word is a banned word/phrase, False otherwise.

        word - string
        """
        return self.tree[word]
