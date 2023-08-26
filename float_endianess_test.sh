#!/bin/bash

cc=$1
if ! [[ -f "float_endianess_test" ]]; then
    eval "${cc} ./float_endianess_test.c -o float_endianess_test"
fi
./float_endianess_test
