# antispam

## About
The script is an example of a very simple program for spam detection. It was
created as a school project. It's implemented in Python3 and it uses the
following criterias to mark an email as a spam:
- the subject of the message is written by capital letters **only**
- the host the message is sent from is stored in a **spam database**
- the subject or the body of the message contains one or more **banned words**
or phrases

Emails are expected to be in .eml format. A wrapper around
[pygtrie](https://github.com/google/pygtrie) library was implemented to create
a trie structure to be used for searching banned words.

## Install
```
$ virtualenv -p python3 .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
$ ./antispam.py EMAIL_PATH [EMAIL_PATH, [...]]
```
