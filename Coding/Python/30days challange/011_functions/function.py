
# Python functions

# Function without parameter and return statement

def my_name():

    first_name = "Alex"
    last_name = "Mwangi"

    print(f"My name is {first_name} {last_name}")

my_name()

# Function without parameter and but with a return statement

def my_name():

    first_name = "Alex"
    last_name = "Mwangi"

    full_name = first_name + ' ' + last_name

    return full_name

print(f"My name is {my_name()}")

# Function with parameter

def my_name(first_name, last_name):

    full_name = first_name + ' ' + last_name
    return full_name

print(f"My name is {my_name("Alex", "Mwangi")}")

# Sum of numbers

def sum_of_numbers():
    total = 0

    for num in range(1, 10+1):
        total += num

    print(total)

sum_of_numbers()