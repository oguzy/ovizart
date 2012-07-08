#!/bin/bash

find ./ -iname "*.pyc"  | xargs rm -rfv
find ./ -iname "*~"  | xargs rm -rfv
find ./ -iname "*.swo"  | xargs rm -rfv
find ./ -iname "*.swn"  | xargs rm -rfv
