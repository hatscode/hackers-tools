
# Normal function
def greet(hello):
    return hello

# Higher order function
def my_func(func):

    func = "Hello world"

    return func

print(my_func(greet))


# area
import math
def my_function(radius):
    return radius

def area_of_circle(area):
    radius = 7

    return math.pi * radius**2

print(area_of_circle(my_function))


