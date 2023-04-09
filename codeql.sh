#!/bin/bash
for filename in JS/*; do
 find JS/ -type f -not -name "*.*" -print0 | xargs -0 rename 's/(.)$/$1.js/'
 rm -rf DB/
 rm -rf JS2/
 mkdir JS2/
 cp $filename JS2/code.js
 if [ -f "Scans/$filename" ]; then
    echo "Skipping $filename"
    continue
 fi
 if [ -d "Scans/$filename" ]; then
    echo "Skipping $filename"
    continue
 fi
 cd JS2
 ../codeql/codeql database create --language=javascript ../DB/
 ../codeql/codeql database analyze ../DB/ --format=sarifv2.1.0 --output=../Scans/$filename
 cd ..
 rm -rf JS2/
done
