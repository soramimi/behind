TARGET = behind
TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt
DESTDIR = $$PWD/_bin

gcc:QMAKE_CXXFLAGS += -Wno-switch

SOURCES += \
    src/Behind.cpp \
    src/TransactionIdGenerator.cpp \
    src/inetresolver.cpp \
    src/main.cpp \
    src/misc.cpp \
    src/network.cpp \
    src/rwfile.cpp

HEADERS += \
    src/Behind.h \
    src/TransactionIdGenerator.h \
    src/inetresolver.h \
    src/misc.h \
    src/network.h \
    src/rwfile.h
