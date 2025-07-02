#!/bin/python3
# -*- coding: utf-8 -*-

"""Main entry point for the Python application."""

def main():

    first_number = 10
    second_number = 20  
    total = first_number + second_number
    return total

def run():
    """Run the main function and print the result."""
    result = main()
    print(f"The sum of the numbers is: {result}")

if __name__ == "__main__":
    run()
# This code defines a simple Python application that calculates the sum of two numbers.
# The main function performs the addition, and the run function prints the result.