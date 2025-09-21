package demo

default can_access = false

can_access if { split(input.path, "/")[1] == input.role }
