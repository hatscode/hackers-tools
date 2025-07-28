# syntax
# while condition:
# code goes here

# Example

count = 0
while count < 5:
    print(count)
    count = count + 1
    if count == 3:
        break

  # syntax
# while condition:
#  code goes here
#   if another_condition:
#       continue

# Example

count = 0
while count < 5:
    if count == 3:
        count = count + 1
        continue
    print(count)
    count = count + 1


# for loop 

# syntax
# for iterator in lst:
#    code goes here

# example

numbers = [0, 1, 2, 3, 4, 5]
for number in numbers: # number is temporary name to refer to the list's items, valid only inside this loop
    print(number)       # the numbers will be printed line by line, from 0 to 5


language = 'Python'
for letter in language:
    print(letter)


for i in range(len(language)):
    print(language[i])


    