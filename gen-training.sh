#!/bin/bash

find ../code/testcases/BuildExes/ -name '*.ground' | xargs -P 16 -I foo bash -c 'F=$(dirname foo)/$(basename foo .ground); echo $F; python3 gen-training.py $F{.ground,,.training}'