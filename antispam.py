#!/bin/python3

# #######################
# Project: antispam
# Author: Martin Kopec
# #######################

import argparse
import email
import spam_lists
import sys

try:
    from trie import Trie
except ModuleNotFoundError:
    sys.stderr.write("Failed to load modules.")

# load banned words
banned_words_EN = open('./banned_words_EN.txt', 'r').read().splitlines()
swear_words_EN = open('./swear_words_EN.txt', 'r').read().splitlines()

t = Trie()
t.init(banned_words_EN)
t.init(swear_words_EN)


class Email:
    """
    Email class represents an email, implements operations over it
    and parses stores information about it
    """

    def __init__(self, email_path, verbose=False, strictness=1):
        """Initializes an email.

        verbose - If True prints reason why the mail was marked as spam,
                  default is False
        strictness - Represents how many banned words to be found is needed
                     to clasify the email as spam.
                     0 tries to find all, but if at least one is find,
                     the email will be marked as spam.
                     Default value is 1
        """
        self.email_path = email_path
        self.parsed = email.message_from_file(open(email_path, 'r'))
        self.sender = self.parsed['from']
        self.subject = self.parsed['subject']
        self.body = self._parse_body(
            email.message_from_string(str(self.parsed)))
        self.is_spam = False
        self.reason = None
        self.verbose = verbose
        self.strictness = strictness

    def _parse_body(self, string_msg):
        """Returns only the email body.

        string_msg - whole email message as string
        """
        if string_msg.is_multipart():
            for payload in string_msg.get_payload():
                return payload.get_payload()
        else:
            return string_msg.get_payload()

    def print_is_spam(self):
        """
        Prints if the email is a spam or not and returns True/False
        accordingly.
        """
        if self.is_spam:
            if not self.verbose:
                self.reason = ""
            else:
                self.reason = "- " + self.reason
            print(self.email_path, "- SPAM", self.reason)
            return True
        else:
            return False

    def examine_header(self):
        """Examines the header of an email.

        Check the subject and the host the email was sent from for a spam.
        """
        try:
            host_from = self.sender.split('@')[1].replace(">", "")
        except IndexError:
            host_from = self.parsed['from']

        # check if the host is in the spam database
        self.check_host_for_spam(host_from)

        # get the email subject
        if contains_only_capital_letters(self.subject):
            self.is_spam = True
            self.reason = "Subject contains only capital letters"
            return

        # check for banned words in the subject
        found = self.check_for_banned_words(self.subject)
        if found:
            self.is_spam = True
            self.reason = "Subject contains banned words: " + ", ".join(found)

    def check_host_for_spam(self, host):
        """Checks if the given host is in the spam database.spam_lists

        host - host address as string
        """
        try:
            if host in spam_lists.SPAMHAUS_DBL:
                self.is_spam = True
                self.reason = "The host address is registered as a spam"
        except spam_lists.exceptions.InvalidHostError:
            self.is_spam = True  # ???
            self.reason = "Invalid host: " + host

    def _contains_banned_word(self, text):
        """
        Iterates over given text input until it doesn't match a prefix
        of a banned word. If a full match with a banned word is found,
        returns True, otherwise returns False.

        text - string
        """
        q = []
        for i in range(len(text)):
            q.append(text[i])
            word = "".join(q)
            if not t.banned_word_prefix(word):
                return False
            try:
                # check, if the following char is a one of the delimiters
                # to avoid matching a prefix of an another word in the text
                delimiter = [" ", "-", ",", "=", "!", "?", "\"", ")", ">",
                             "<", "*", "~", ":", "$"]
                if t.is_banned_word(word) and text[i + 1] in delimiter:
                    return word
            except IndexError:
                # it's the end of the input
                return word

    def check_for_banned_words(self, text):
        """Searches for banned words in the given text.

        text - string
        Returns True if found any banned word, False otherwise.
        """
        found = []
        for i in range(len(text)):
            ret = self._contains_banned_word(text[i:])
            if ret:
                found.append(ret)

                if len(found) == self.strictness:
                    return found
        return False if not found else found

    def examine_body(self):
        found = self.check_for_banned_words(self.body)
        if found:
            self.is_spam = True
            self.reason = "Contains banned words: " + ", ".join(found)


def contains_only_capital_letters(sentence):
    """
    Returns True if the string contains only capital letters,
    False otherwise.

    sentence - string
    """
    ret = True
    for x in sentence:
        if x.isspace():
            continue
        ret = x.isupper()
        if not ret:
            return ret
    return ret


if __name__ == "__main__":

    # arguments handler
    parser = argparse.ArgumentParser(description='Python script for a spam ' +
                                                 'detection')

    parser.add_argument('EMAILS', nargs='+', help='Path(s) to the email(s) ' +
                                                  'file(s) to be checked')

    parser.add_argument('--verbose', action='store_true', help='Print the ' +
                        'reason, why the email was marked as a spam')

    parser.add_argument('--strictness', default=1, type=int,
                        help='Number of banned words found to mark ' +
                        'the email as a spam, number 0 prints all found')

    args = vars(parser.parse_args())

    # iterate over emails and run spam detection
    for email_path in args['EMAILS']:
        try:
            E = Email(email_path, args['verbose'], args['strictness'])
        except FileNotFoundError:
            print("The file was not found: ", email_path)
            continue

        E.examine_header()
        if E.print_is_spam():
            continue

        E.examine_body()
        if E.print_is_spam():
            continue

        print(email_path, "- OK")
