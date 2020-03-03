#!/bin/bash

# Run this in django_bos container in folder /application/source to produce new "permissions" migration & copy fresh result for inspection 
#

rm -rf /usr/local/lib/python3.6/dist-packages/django_permissions-dev-py3.6.egg/permissions/migrations/*

django-admin makemigrations permissions

cp /usr/local/lib/python3.6/dist-packages/django_permissions-dev-py3.6.egg/permissions/migrations/0001_initial.py .