REM Used during development to copy output of "django-admin makemigrations permissions to local folder for inspection
REM and comparison against existing file 0001_initial.py (with suffix ".hold")
REM
docker cp django_bos:/usr/local/lib/python3.6/dist-packages/django_permissions-dev-py3.6.egg/permissions/migrations/0001_initial.py .
docker cp django_bos:/application/source/src/django-permissions/permissions/migrations/0001_initial.py.hold .
