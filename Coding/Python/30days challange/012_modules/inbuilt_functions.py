
# Inbuilt functions

import os # import thr os module
import sys

from statistics import *


# os.chdir("") # Change the directory
# os.mkdir() # Make a directory
# os.rmdir() # Remove a directory
# os.getcwd() # Check the current working directory

#print(sys.argv[0], argv[1],sys.argv[2])  # this line would print out: filename argument1 argument2
# print('Welcome {}. Enjoy  {} challenge!'.format(sys.argv[1], sys.argv[2]))
print(sys.version) # print the version


# The statistics module

ages = [20, 30, 23, 45, 2, 43, 45, 45, 80]

print(mean(ages))
print(mode(ages))
print(median(ages))
print(stdev(ages))

# Math module

import math

print(math.pi)
print(math.sqrt(9))
print(math.pow(2, 3))
print(math.floor(9.83))
print(math.ceil(9.83))

# Random value

from random import random, randint

print(random())
print(randint(1, 10))

# String module

import string

print(string.ascii_letters)
print(string.digits)
print(string.punctuation)