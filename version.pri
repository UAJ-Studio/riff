APP_VERSION = 1.3.0
APP_REVISION = $(shell git rev-parse --short=12 --verify HEAD)
#uncomment the below line in a source package and fill-in the correct revision
#APP_REVISION = <rev-hash>@

ver_info {
    APP_VERSION_FILE = version.cpp
    win32 {
        # Generate at qmake time: the cmd-style echo recipe produces an empty
        # file when make runs recipes through MSYS sh
        WIN_REVISION = $$system(git rev-parse --short=12 --verify HEAD)
        VERSION_LINES = "const char *version = \"$$APP_VERSION\";"
        VERSION_LINES += "const char *revision = \"$$WIN_REVISION\";"
        write_file($$OUT_PWD/$$APP_VERSION_FILE, VERSION_LINES)
    }
    unix {
        revtarget.target = $$APP_VERSION_FILE
        revtarget.commands = echo \
            "\"const char *version = \\\"$$APP_VERSION\\\";" \
            "const char *revision = \\\"$$APP_REVISION\\\";\"" \
            > $$APP_VERSION_FILE
        revtarget.depends = $$SOURCES $$HEADERS $$FORMS $$POST_TARGETDEPS
        QMAKE_EXTRA_TARGETS += revtarget
        POST_TARGETDEPS += $$APP_VERSION_FILE
    }

    SOURCES += $$APP_VERSION_FILE
    QMAKE_DISTCLEAN += $$APP_VERSION_FILE
}

# Windows version resource for the executables (product name and version in
# the file properties, required for code signing): qmake generates
# <target>_resource.rc from these. QMAKE_TARGET_DESCRIPTION is set per .pro.
win32:equals(TEMPLATE, app) {
    VERSION = $$APP_VERSION
    QMAKE_TARGET_PRODUCT = Riff
    QMAKE_TARGET_COMPANY = UAJ-Studio
    QMAKE_TARGET_COPYRIGHT = "GPLv3. Derived from Ostinato (c) 2007-2023 Srivats P."
}
