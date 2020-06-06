# Makefile Module For Develop Team

.SUFFIXES:
.SUFFIXES:  .c .o

WORKDIR=.
INCLDIR=$(WORKDIR)/incl
LIBDIR=$(HOME)/lib
BINDIR=$(HOME)/bin

CC=gcc

INCLFLG= -I$(INCLDIR)
LIBFLG = -L$(LIBDIR)
CFLAG= -c -g $(INCLFLG) 
LIBS = 

VPATH = $(WORKDIR)/src


OBJ7 = itcast_asn1_der.o  itcastderlog.o  mykeymng_msg.o

#当有一个.c发生更新的时, 目标重新生成吗?

libmymessagereal.so: $(OBJ7) 
	$(CC) -shared -fPIC $^ -o $@ 
	
	@cp $@ $(LIBDIR)
# gcc -shared -fPIC itcast_asn1_der.o  itcastderlog.o  keymng_msg.o -o  libmymessagereal.so

#自动推导 把.c===>自动的生成.o
# mykeymng_msg.c
.c.o:    
#	$(CC) -shared -fPIC $(CFLAG) $< -D_ITCAST_OS_LINUX  -DMEMWATCH -DMW_STDIO
	$(CC) -shared -fPIC $(CFLAG) $< -D_ITCAST_OS_LINUX


# 	gcc -shared -fPIC -c -g -I./incl

# make工程是在那个路径下找.c文件 ./ VPATH
	
.PHONY : clean
clean :
	rm  -f *.o
	rm  -f *.s