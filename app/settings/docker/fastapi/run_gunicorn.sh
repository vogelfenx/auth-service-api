#!/bin/bash

source /opt/app/wait_db_up.sh
source /opt/app/run_db_migrations.sh

gunicorn -k uvicorn.workers.UvicornWorker --log-level info --bind 0.0.0.0:8000  src.main:app
