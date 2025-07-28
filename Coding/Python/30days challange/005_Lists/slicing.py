
# Positive indexing

my_list = ["alex", 120, 10j, 4.5, True]

all_items = my_list[0:] # prints all items from the list

some_items = my_list[1:3]
type_of_item = my_list[:3]


print(all_items)
print(some_items)
print(type(type_of_item))
print(type_of_item)

# Negative indexing
fruits = ['mango', 'orange', 'banana', 'lemon']
all_fruits = fruits[-4:]
orange_and_mango = fruits[-4:-2]

print(all_fruits)
print(orange_and_mango)


# Checking if an item exists in a list
lst = ['Alex', 'Mwangi', 'Mungai']
does_exist = 'Alex' in lst

print(does_exist)
print(len(lst))




# Adding items in a list
my_list = [] # create an empty list
my_list.append("Mango")
print(my_list)

# Inserting items in a list
my_list = ['Hack', 'Code', 'Gym']
my_list.insert(3, "Sleep")
print(my_list)

print('Hello world!')

name = input("Please entter the name: ")


print(name)




