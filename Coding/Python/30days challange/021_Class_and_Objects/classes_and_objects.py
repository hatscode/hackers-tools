
# Python is object oriented
# A claa is a blueorint or template for creating objects

# syntax for creating a class 
'''
    class class_name:
    block of code
'''

# example

class person:
    pass

print(person)


# creating an object 
#  we can create an object by calling the class

# example 
class dog:

    pass

d = dog() 

print(d)


# Class contructor
# Python has a class constructor __init__ with a self parameter which is a reference of to the curent instance of the class
# Example

class person:

    def __init__(self, first_name, second_name):
        self.first_name = first_name
        self.second_name = second_name

# Create an object of the class
p = person("Alex", "Mwangi")
print(f"Hello {p.first_name} {p.second_name}! Do you enjoy programming?")

# Finding the area of a circle using a class

# Define the class
import math

class Area:

    # Define the __init__ method
    def __init__(self, radius):
        # Atributes
        self.radius = radius

    def find_area(self):
        return f"The area is {math.pi * self.radius ** 2}"

# Creating an object of the class area
a = Area(7)
print(a.find_area())        
