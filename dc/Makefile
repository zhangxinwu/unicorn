CC = cc
CXX_FLAG = -g -I../include  -lm 

all: main.cpp ../libb/libunicorn.a
	${CC} $^ ${CXX_FLAG} -lpthread

arm64: main.cpp ../lib64/libunicorn.a
	aarch64-linux-android31-clang $^ ${CXX_FLAG}

arm: main32.cpp ../lib32/libunicorn.a
	armv7a-linux-androideabi31-clang++ $^ ${CXX_FLAG} -lc++

so: main.cpp ../lib64/libunicorn.a
	aarch64-linux-android31-clang $^ ${CXX_FLAG} -lc++_static -llog -fPIC -shared -o libanduni.so

so32: main32.cpp ../lib32/libunicorn.a
	armv7a-linux-androideabi31-clang $^ ${CXX_FLAG} -lc++_static -llog -fPIC -shared -o libanduni.so

clean:
	$(shell rm a.out)