#1. Exercises: Day 13
# Filter only negative and zero in the list using list comprehension
# numbers = [-4, -3, -2, -1, 0, 2, 4, 6]

numbers = [-4, -3, -2, -1, 0, 2, 4, 6]

filtered_numbers = [num for num in numbers if num <= 0]

print(filtered_numbers)

#2. Flatten the following list of lists of lists to a one dimensional list :
# list_of_lists =[[[1, 2, 3]], [[4, 5, 6]], [[7, 8, 9]]]
# output
# [1, 2, 3, 4, 5, 6, 7, 8, 9]

list_of_lists =[[[1, 2, 3]], [[4, 5, 6]], [[7, 8, 9]]]

flatten_numbers = [number for i in list_of_lists for number in i]

list_of_numbers = [number for i in flatten_numbers for number in i]

print(list_of_numbers)


# Flatten the following list to a new list:

# countries = [[('Finland', 'Helsinki')], [('Sweden', 'Stockholm')], [('Norway', 'Oslo')]]
# output:
# [['FINLAND','FIN', 'HELSINKI'], ['SWEDEN', 'SWE', 'STOCKHOLM'], ['NORWAY', 'NOR', 'OSLO']]

countries = [[('Finland', 'Helsinki')], [('Sweden', 'Stockholm')], [('Norway', 'Oslo')]]