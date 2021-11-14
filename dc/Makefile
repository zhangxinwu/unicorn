CC = cc
CXX_FLAG = -g -I../include  -lm 

all: main.cpp ../libb/libunicorn.a
	${CC} $^ ${CXX_FLAG} -lpthread

arm64: main.cpp ../lib64/libunicorn.a
	aarch64-linux-android31-clang $^ ${CXX_FLAG}

arm: main.cpp ../lib32/libunicorn.a
	armv7a-linux-androideabi31-clang $^ ${CXX_FLAG}

clean:
	$(shell rm a.out)