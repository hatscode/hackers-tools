"""
Get user input using input(“Enter your age: ”). 
If user is 18 or older, give feedback: You are old enough to drive. 
If below 18 give feedback to wait for the missing amount of years. Output:

Enter your age: 30
You are old enough to learn to drive.
Output:
Enter your age: 15
You need 3 more years to learn to drive.
"""

# age = input("Enter your age: ")
# age = int(age)
# if age >= 18:
#     print("You are old enough to learn to drive.")

# elif age > 0 and age < 18:
#     print(f"You need {18 - age} more years to learn to drive")

# else:
#     print("Invalid age")


"""
    Compare the values of my_age and your_age using if … else. 
    Who is older (me or you)? Use input(“Enter your age: ”) to get the age as input. \
    You can use a nested condition to print 'year' for 1 year difference in age, 'years' for 
    bigger differences, and a custom text if my_age = your_age. Output:

    Enter your age: 30
    You are 5 years older than me.
"""

# my_age = 27
# your_age = input("Enter your age: ")
# your_age = int(your_age)

# if my_age < your_age:
#     if (your_age - my_age) == 1:
#         print(f"You are {your_age - my_age} year older than me.")
#     else:
#         print(f"You are {your_age - my_age} years older than me.")

# elif my_age == your_age:
#     print("We are age mates.")


"""
    Get two numbers from the user using input prompt. 
    If a is greater than b return a is greater than b, if a is less b return a 
    is smaller than b, else a is equal to b. Output:

    Enter number one: 4
    Enter number two: 3
    4 is greater than 3
"""

# number_one = input("Enter number one: ")
# number_one = int(number_one)

# number_two = input("Enter number two: ")
# number_two = int(number_two)

# if number_one > number_two:
#     print(f"{number_one} is greater than {number_two}")
# elif number_one == number_two:
#     print(f"{number_one} is equal to {number_two}")
# else:
#     print(f"{number_one} is less than {number_two}")


"""
The following list contains some fruits:

fruits = ['banana', 'orange', 'mango', 'lemon']

If a fruit doesn't exist in the list add the fruit to the list and print the modified list. 
If the fruit exists print('That fruit already exist in the list')

"""

fruits = ['banana', 'orange', 'mango', 'lemon']
add_fruit = input("Enter a friut to add in the list: ")
add_fruit = str(add_fruit)

if add_fruit in fruits:
    print("That fruit already exist in the list")
    
else:
    fruits.append(add_fruit)
    print(fruits)
