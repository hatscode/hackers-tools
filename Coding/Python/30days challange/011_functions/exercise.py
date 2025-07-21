"""
    1. Declare a function add_two_numbers. It takes two parameters and it returns a sum.
"""

def add_two_numbers(first_number, second_number):

    total = first_number + second_number

    return total

print(f"The sum is {add_two_numbers(14, 20)}") # 34


"""
    2. Area of a circle is calculated as follows: area = π x r x r. 
    Write a function that calculates area_of_circle.
"""
import math

def area_of_circle(radius):

    area = math.pi * radius**2

    return area

print(f"The area of the circle is {area_of_circle(7): .2f}")


"""
    3. Write a function called add_all_nums which takes arbitrary number of arguments and sums all 
    the arguments. Check if all the list items are number types. If not do give a reasonable feedback.
"""

def add_all_numbers(*args):
    total = 0
    for num in args:
        if not isinstance(num, (int, float)):
            return "All arguments must be numbers."
        total += num
    return total

print(f"{add_all_numbers(1, 2, 3.5)}")  # Valid input
print(f"{add_all_numbers(1, 'a', 3)}")  # Invalid input

    
    