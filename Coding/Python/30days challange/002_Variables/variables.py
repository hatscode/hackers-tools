# In python there are 2 types of variables

# 1. Local variables 
# These are variables that are created inside a function

def localVariable():

    myName = "Alex"

    print("MY name is ", myName)

localVariable() # call the function

# 2. Global variables
# These are variables that are created outside the function

myMessage = "Hello world"

def globalVariable(): # Define the function

    print("My message is ", myMessage)

globalVariable()

# 3. Using the global keyword
# The global keyword can be used to inside a function but be accessed inside or outside that function

greetings = "Hello world"

def myFunction():

    global global_variable

    global_variable = "I am a global variable. I can be accessed inside and outside a function."
    
    print(global_variable)

myFunction() # call the function

# access the global_variable outside a function

print(global_variable)

