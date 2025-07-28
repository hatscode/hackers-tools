
#  syntax
#  [i for i in iterable if expresion]


# for example you want to change a string to alist, you can use many methods

# method 1
string = "My string"

my_list = list(string) # Change the string to a list

print(my_list)

# meethod 2: using list coprehension
string = "My string"

my_list = [i for i in string]

print(my_list)

# Example 2: for example you want to generate a list of numbers you can use a list comprension
# List of numbers
list_of_numbers = [num for num in range(1, 10+1)]

print(list_of_numbers)

# Squre of numbers
list_of_squres = [num * num for num in range(1, 10+1)]

print(list_of_squres)

# List of numbers and their squres
list_of_nums_and_squres = [(num, num * num) for num in range(1, 10+1)]

print(list_of_nums_and_squres)


# List comprehension can be combined with if expresion
number = 30

odd_numbers = [odd for odd in range(1, number+1) if odd%2 == 1]

print(odd_numbers)

#  Filtering positive even numbers
numbers = [-8, -7, -3, -1, 0, 1, 3, 4, 5, 7, 6, 8, 10]

even_numbers = [even for even in numbers if even%2 == 0 and even > 0]

print(even_numbers)

# Lambda function
# syntax
# lambda par1, par2, ...: expresion
add_numbers = lambda first_number, second_number: first_number + second_number

print(add_numbers(10, 20)) # prints 30

