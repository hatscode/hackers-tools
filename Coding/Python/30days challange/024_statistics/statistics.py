
# Creating numpy arrays

import numpy as np

python_list = [10, 20, 30, 40, 50]

print(python_list) # This will print the python list

python_array = np.array(python_list) # This will change the list to an array

print(python_array) # This will print the array

python_array = np.array(python_list, dtype=float) # change the datatype to an array

print(", ".join(map(str, list(python_array))))

