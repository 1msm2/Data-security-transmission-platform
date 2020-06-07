# Makefile 
.SUFFIXES:
.SUFFIXES:  .c .o

all: testmsgreal


CC	= gcc


WORKDIR=.
LIBDIR=$(HOME)/lib
LIBS = -L$(LIBDIR) -lmymessagereal
OUTDIR=$(HOME)/bin

INCLDIR=$(WORKDIR)/incl
INCLFLG= -I$(WORKDIR)/incl
CFLAG= $(INCLFLG) -g -c -Wall

VPATH = $(WORKDIR)/src

OBJ1 = keymng_msg_test.o 

testmsgreal:$(OBJ1)
	$(CC) $(LIBS) $^ -o $@ 

# gcc -L/home/it01/lib -lmymessagereal keymng_msg_test.o -o testmsgreal



# 把所有的。c 生成。o
# gcc -I./incl -g -c -Wall keymng_msg_test.c -o keymng_msg_test.o
#.o:.c
#keymng_msg_test.c====>keymng_msg_test.o


.c.o:
	$(CC) $(CFLAG) $<

.PHONY:clean
clean:
	rm *.o
	rm testmsgreal
	rm *.ber
	rm *.txt
	


