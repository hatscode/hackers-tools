
'''
    We use the open() buit-in function in python to hundle data
    syntax
    open(filename, mode) # mode(r, a, w, x, t,b)  could be to read, write, update
'''

# Example
f = open(r"C:\Users\alexm\Desktop\Python programms\30days challange\019_FIle_Hundling\index.html")
text = f.read()

print(type(text)) # Type of the conten in the file
print(text) # Reads the entire text in the file

f.close()

f = open(r"C:\Users\alexm\Desktop\Python programms\30days challange\019_FIle_Hundling\index.html")

text = f.read(40) # Reads the first 40 characters in the file
print(text)

f.close()

f = open(r"C:\Users\alexm\Desktop\Python programms\30days challange\019_FIle_Hundling\index.html")

text = f.readline() # Reads the first line of the file only
print(text)

f.close()

with open(r"C:\Users\alexm\Desktop\Python programms\30days challange\019_FIle_Hundling\index.html") as file:
    text = file.read().splitlines()
    print(text)
    print(len(text))
    print(", \n".join(text))

f.close