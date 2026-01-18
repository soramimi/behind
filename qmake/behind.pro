TARGET = behind
TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt
DESTDIR = $$PWD/../_bin

gcc:QMAKE_CXXFLAGS += -Wno-switch

SOURCES += \
    ../src/Behind.cpp \
    ../src/ConfigParser.cpp \
    ../src/Global.cpp \
    ../src/Logger.cpp \
    ../src/RandomNumber.cpp \
    ../src/TransactionIdGenerator.cpp \
    ../src/inetresolver.cpp \
    ../src/main.cpp \
    ../src/misc.cpp \
    ../src/network.cpp \
    ../src/rwfile.cpp

HEADERS += \
    ../src/Behind.h \
    ../src/ConfigParser.h \
    ../src/Global.h \
    ../src/Logger.h \
    ../src/RandomNumber.h \
    ../src/TransactionIdGenerator.h \
    ../src/inetresolver.h \
    ../src/misc.h \
    ../src/network.h \
    ../src/rwfile.h
