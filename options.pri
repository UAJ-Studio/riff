!win32:QMAKE_CXXFLAGS += -isystem $$[QT_INSTALL_HEADERS] -std=c++11
win32:QMAKE_CXXFLAGS += -std=c++11
CONFIG(debug, debug|release): QMAKE_CXXFLAGS_WARN_ON += -Wall -W -Wextra -Werror
CONFIG(debug, debug|release): QMAKE_CXXFLAGS_WARN_ON += -Wno-deprecated-declarations
# static Qt pulls in OpenSSL (libcrypto.a), which newer MSYS2 builds link
# against bcrypt; QMAKE_LIBS goes after the Qt libraries on the link line
win32:QMAKE_LIBS += -lbcrypt
