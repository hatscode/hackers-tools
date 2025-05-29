#!/bin/bash

name='Alex'

echo $name
readonly name #prevents a variable from beign updated

age=20

echo $age
unset age #removes value from a variable
echo $age:'is empty'