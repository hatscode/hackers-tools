
# if, elif and else

"""
    syntax of if statement
    if condition:
        block of code
"""
# Example

number = 100
if number > 0:
    print(f"{number} is positive.")

"""
    else condition
    syntax
    if condition:
        block of code
    else:
        block of code
"""
# Example
number = -100
if number > 0:
    print(f"{number} is positive.")

else:
    print(f"{number} is negative.")

"""
    elif condition
    syntax
    if condition:
        block of code
    elif condition:
        block of code
    else:
        block of code
"""
# Example
temperature = -37

if temperature > 100:
    print("You have fever.")

elif temperature == 37:
    print("You are healthy.")

else:
    print("You have cold")


"""
    Shorthand of if else statement
    syntax
    code if condition else code
"""
# Example
number = 110
number = int(number)
print(f"{number} is positive.") if number > 0 else print(f"{number} is negative.")

"""
    Netsted conditions
    syntax
    if condition:
        if condition:
            code
        else:
            code
    elif condition:
        if condition:
            code
    else:
        code
"""