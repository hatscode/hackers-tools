
# Python errors

# 1. Syntax error
# print 'Hello world' # This displays a syntax error
print('Hello world') # This is the correct syntax

# Name error
# print(name) # This will print an error because the name is not defined

name = "Alex Mwangi"
print(f"{name} is of type {type(name)}") # This is the correct syntax because the name is defined

# IndexError
my_list = [1,2,4,5,15]
# print(my_list[5]) # This will print and index error because 5 is out of range
print(my_list[4])

# ModuleNotFoundError
# import maths : This will generate an error becaause the module maths does no exist
import math # This is the correct syntax
print(math.pi)

# AttributeError
import math
# print(math.PI) : # This will print an attribute error module 'math' has no attribute 'PI'. Did you mean: 'pi'?
print(math.pi) # This is the correct syntax

# KeyError
# This occurs when you are trying to access a key value that does not exist
my_dictionary = {
    "name": "Aleex",
    "Age": 54,
    "Hobby": "Gaming"
}
# print(my_dictionary['height']) : This will print a KeyError
print(my_dictionary['Age'])

# TypeError
# print(3 + '4') : This will print a TypeError because the string can't be added to an int
print(f"My name is {name + " Mungai"} and I am {my_dictionary['Age'] + 6} years old") # This is the correct syntax

# ImportError
# from math import power : This will generate an error 
