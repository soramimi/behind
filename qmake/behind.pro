TARGET = behind
TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt
DESTDIR = $$PWD/../_bin

INCLUDEPATH += $$PWD/../src

gcc:QMAKE_CXXFLAGS += -Wall -Wextra -Werror=return-type -Werror=trigraphs -Wno-switch -Wno-reorder -Wno-unused-parameter -Wno-unused-parameter

SOURCES += \
    ../src/Behind.cpp \
    ../src/ConfigParser.cpp \
    ../src/DomainFilter.cpp \
    ../src/LineReader.cpp \
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
    ../src/DomainFilter.h \
    ../src/LineReader.h \
    ../src/Logger.h \
    ../src/RandomNumber.h \
    ../src/TransactionIdGenerator.h \
    ../src/inetresolver.h \
    ../src/misc.h \
    ../src/network.h \
    ../src/rwfile.h

DISTFILES += \
    ../scripts/behind.conf
