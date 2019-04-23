#! /bin/bash
if [ -e files.txt ];
then
	xargs rm -rf < files.txt
fi;
python setup.py install --record files.txt

