CC ?= armv7a-linux-androideabi32-clang
CC = cc
CXX_FLAG ?= -g -I../include  -lpthread -lm

a.out: *.cpp ../libunicorn.a
	${CC} $^ ${CXX_FLAG}

all: a.out

clean:
	$(shell rm a.out)