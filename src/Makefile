TARGET=nxdomain
CXXFLAGS=-O2 -std=c++17


all: $(TARGET)

$(TARGET): main.o nxdomain.o rwfile.o network.o inetresolver.o
	g++ -o $@ $^
	strip $@

clean:
	-rm $(TARGET)
	-rm *.o


install: $(TARGET)
	install $(TARGET) /usr/local/bin
