TEMPLATE = app
win32: TARGET = riff-agent
CONFIG += qt ver_info c++11
addon: CONFIG -= ver_info
QT += network script xml
QT -= gui
linux*:system(grep -q IFLA_STATS64 /usr/include/linux/if_link.h): \
    DEFINES += HAVE_IFLA_STATS64
INCLUDEPATH += "../common"
INCLUDEPATH += "../rpc"
win32 {
    # Support Windows Vista and above only
    DEFINES += WIN32_LEAN_AND_MEAN NTDDI_VERSION=0x06000000 _WIN32_WINNT=0x0600
    DEFINES += HAVE_REMOTE WPCAP
    # Newer Npcap SDK bpf.h no longer defines this; packet32.h needs it to
    # avoid redefining struct bpf_program/bpf_insn
    DEFINES += BPF_MAJOR_VERSION=1
    CONFIG += console
    QMAKE_LFLAGS += -static-libgcc -static-libstdc++
    LIBS += -lwpcap -lpacket -liphlpapi
    CONFIG(debug, debug|release) {
        LIBS += -L"../common/debug" -lostproto
        LIBS += -L"../rpc/debug" -lpbrpc
        POST_TARGETDEPS += \
            "../common/debug/libostproto.a" \
            "../rpc/debug/libpbrpc.a"
    } else {
        LIBS += -L"../common/release" -lostproto
        LIBS += -L"../rpc/release" -lpbrpc
        POST_TARGETDEPS += \
            "../common/release/libostproto.a" \
            "../rpc/release/libpbrpc.a"
    }
} else {
    LIBS += -lpcap
    LIBS += -L"../common" -lostproto
    LIBS += -L"../rpc" -lpbrpc
    POST_TARGETDEPS += "../common/libostproto.a" "../rpc/libpbrpc.a"
}
linux {
    INCLUDEPATH += "/usr/include/libnl3"
    LIBS += -lnl-3 -lnl-route-3
}
LIBS += -lm
LIBS += -lprotobuf
HEADERS += drone.h \
    pcaptransmitter.h \
    myservice.h \
    streamtiming.h
SOURCES += \
    devicemanager.cpp \
    device.cpp \
    emuldevice.cpp \
    drone_main.cpp \
    drone.cpp \
    portmanager.cpp \
    abstractport.cpp \
    pcapport.cpp \
    pcapsession.cpp \
    pcaptransmitter.cpp \
    pcaprxstats.cpp \
    pcaptxstats.cpp \
    pcaptxthread.cpp \
    pcaptxttagstats.cpp \
    bsdhostdevice.cpp \
    bsdport.cpp \
    linuxhostdevice.cpp \
    linuxport.cpp \
    linuxutils.cpp \
    params.cpp \
    streamtiming.cpp \
    turbo.cpp \
    winhostdevice.cpp \
    winpcapport.cpp 
SOURCES += myservice.cpp 
SOURCES += pcapextra.cpp 
SOURCES += packetbuffer.cpp

QMAKE_DISTCLEAN += object_script.*

include (../install.pri)
include (../version.pri)
include (../options.pri)
