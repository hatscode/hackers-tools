
import pandas as pd
import numpy as np

my_list = [1, 2, 3, 4, 5]

# Creating pandas with default index
series = pd.Series(my_list)
print(series)

# Creating pandas with custom index
series = pd.Series(my_list, index=[1, 2, 3, 4, 5])
print(series)


fruits = ["Banana", "Orange", "Mango", "Apple"]

fruit = pd.Series(fruits, index=[1, 2, 3, 4])


print(fruit)

data = [
    ['Asabeneh', 'Finland', 'Helsink'], 
    ['David', 'UK', 'London'],
    ['John', 'Sweden', 'Stockholm']
]
df = pd.DataFrame(data, columns=['Names','Country','City'])
print(df)