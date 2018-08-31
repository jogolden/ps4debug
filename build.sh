#!/bin/bash
# I decide to just clean it all then build from scratch each go around lol
# golden :P

clean_build() {
    cd ps4-ksdk
    make clean
    cd ..
    
    cd ps4-payload-sdk/libPS4/
    make clean
    cd ../../

    cd debugger
    make clean
    cd ..
    
    cd kdebugger
    make clean
    cd ..

    cd installer
    make clean
    cd ..
}

build_submodules() {
    cd ps4-ksdk
    make
    cd ..
    
    cd ps4-payload-sdk/libPS4/
    make
    cd ../../
}

build_debugger() {
    cd debugger
    make
    cd ..
}

build_kdebugger() {
    cd kdebugger
    make
    cd ..
}

build_installer() {
    cd installer
    make
    cd ..
}

if (( $# == 1 ));
then
    if [ $1 == "clean" ]
    then
        echo "cleaning build..."
        clean_build
    fi
fi

echo "ps4debug building..."

echo "=> submodules..."
build_submodules
echo "=> debugger..."
build_debugger
echo "=> kdebugger..."
build_kdebugger
echo "=> installer..."
build_installer

cp ./installer/installer.bin ./ps4debug.bin

echo ""
echo "enjoy ps4debug! golden :P"
