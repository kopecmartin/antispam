#!/bin/python3

# #######################
# Project: antispam
# Author: Martin Kopec
# #######################

import argparse
from collections import Counter
import email
import itertools
import re
import spam_lists

# load banned words
banned_words_EN = open('./banned_words_EN.txt', 'r').read().splitlines()
swear_words_EN = open('./swear_words_EN.txt', 'r').read().splitlines()


class Email:
    def __init__(self, email_path, verbose):
        self.email_path = email_path
        self.parsed = email.message_from_file(open(email_path, 'r'))
        self.is_spam = False
        self.reason = None
        self.error = None  # ???
        self.verbose = verbose

    def print_is_spam(self):
        if self.is_spam:
            print(self.email_path, "- SPAM -", self.reason)
            return True
        else:
            return False

    def examine_header(self):
        # get host the mail was sent from and check if the host
        # is in the spam database
        try:
            host_from = self.parsed['from'].split('@')[1].replace(">", "")
        except IndexError:
            host_from = self.parsed['from']

        self.check_host_for_spam(host_from)

        # get email subject
        subject = self.parsed['subject']
        # print("subject - ", subject)  # debug
        if contains_only_capital_letters(subject):
            self.is_spam = True
            self.reason = "Subject contains only capital letters"

    def check_host_for_spam(self, host):
        # print("host - ", host)  # debug
        try:
            if host in spam_lists.SPAMHAUS_DBL:
                self.is_spam = True
                self.reason = "The host address is registered as a spam"
        except spam_lists.exceptions.InvalidHostError:
            self.is_spam = True  # ???
            self.reason = "Invalid host: " + host

    def examine_body(self):
        # print(self.parsed)
        lsts = banned_words_EN + swear_words_EN
        found = list(filter(lambda word:
                            str(word) in str(self.parsed), lsts))
        # quick_found = list(filter(lambda word:
        #                   str(word) in str(self.parsed), lsts))
        # text = str(self.parsed)
        # found = list(itertools.chain.from_iterable(list(map(lambda word:
        #             re.findall(str(word), text),
        #            quick_found))))

        print(found)
        # print(list(Counter(found)))
        # if len(list(Counter(found))) > 1:
        if len(found) > 1:
            self.is_spam = True
            words = str(Counter(found)) if self.verbose else ""
            self.reason = "Contains banned words " + words


def contains_only_capital_letters(sentence):
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

    parser.add_argument('PATHS', nargs='+', help='Path(s) to the email(s) ' +
                                                 'file(s) to be checked')
    parser.add_argument('--verbose', action='store_true', help='')

    args = vars(parser.parse_args())

    # iterate over emails and run spam detection
    for email_path in args['PATHS']:

        try:
            E = Email(email_path, args['verbose'])
        except FileNotFoundError:
            print("The file was not found: %s", email_path)
            continue

        E.examine_header()
        if E.print_is_spam():
            continue

        E.examine_body()
        if E.print_is_spam():
            continue

        print(email_path, "- OK")
