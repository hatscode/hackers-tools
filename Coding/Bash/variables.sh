#!/bin/bash

name='John Doe'

echo $name
readonly name #prevents a variable from beign updated

age=20

echo $age
unset age #removes value from a variable
echo $age:'is empty'

# Using a variable in a string
greeting="Hello, $name! You are $age years old."
echo $greeting