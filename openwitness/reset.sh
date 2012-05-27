#!/bin/bash

cd uploads
rm -rf *
cd ..
mongo
mongo trafficdb --eval "db.dropDatabase(); exit;"
cd ..
bin/django syncdb

