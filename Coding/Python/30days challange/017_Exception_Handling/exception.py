
# Python exception Handling

# Syntax
# try:
#     code in this block if things go well

# except:
#     code in this block if things go wrong


# Handling of errors prevents our applications from crashing

try:
    print("Hello there!")

except:
    print("Something went wrong")


# Another example


try:
    import datetime

    name = input("Enter your name: ")
    year_born = input("Enter year you were born: ")
    # year_born = int(year_born)

    now = datetime.datetime.now()
    this_year = now.year

    age = this_year - year_born

    print(f"Hello {name}. You are {age} years old!")

except Exception as e:
    print("Something went wrong")
    print(e)