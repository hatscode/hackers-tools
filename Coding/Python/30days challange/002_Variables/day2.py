#           PYTHON DATATYPES
# Variables can store data of different types
# Datatypes in python include str, int, float, complex, bool, list, turple, dict, range, byte, bytetype 

# You can get the type of a value using the type() function

a = "Hello there"

print (type(a)) # prints <class 'str'>

b = 10

print(type(b)) # prints <class 'int'>

c = 20.4

print(type(c)) # prints <class 'float'>

d = 10j

print(type(d)) # prints <class 'complex'>

e = True

print(type(e)) # prints <class 'bool'>

fruits = ["Mango", "Apple", "Orage"]

print(type(fruits)) # prints <class 'list'>

myInfo = {
    "name" : "Alex Mwangi",
    "Age" : "1000",
    "role" : "Hacker"
}

print(type(myInfo))

print(myInfo)

#           PYTHON NUMBERS
# There are 3 types of numbers in python -> int, float, and complex
x = 4 # int 
y = 10.3 # float
z = 20j # complex

print(x,y,z)
print(type(x))
print(type(y))
print(type(z))

# You can also convert one number to the other
x = 10 # int type
y = float(x) # convert 10 to from int to float

print(y)

#           RANDOM

import random

print(random.randrange(1,10)) # prints a random number

#           CASTING

x = str(10j)
y = float(10)
z = complex(2)

print(x,y,z)

#           PYTHON STRINGS
# Strings can be surounded by single or double quotes in python

firstString = "Hello" # using double quote
secondString = 'World!' # using single quote

print(firstString)
print(secondString)

# multiline strings
multilineString = """
    Hello world!
    I love python programming
    Do you love coding?
"""

print(multilineString)

# Strings are arrays

message = "Hello world"

print(message[1])