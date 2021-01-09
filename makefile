build : del.o
  cc -o del del.o

del.o : del.c
  cc -c del.c
