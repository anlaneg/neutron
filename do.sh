#! /bin/bash
pip install virtualenv
virtualenv venv
virtualenv --system-site-packages venv
#virtualenv -p /usr/bin/python2.7 venv
cd venv
source bin/activate
python -V
apt-get install -y python-subprocess32
cd ..
python setup.py install
pip install -r requirements.txt

#deactivate
