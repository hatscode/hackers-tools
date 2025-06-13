#!/bin/python3

def sum(number_one, number_two):
    number_one_int = convert_integer(number_one)
    number_two_int = convert_integer(number_two)
    return number_one_int + number_two_int

def convert_integer(number_string):
    return int(number_string)

answer = sum('1', '2')
print(answer)  # Output: 3

