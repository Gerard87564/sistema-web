#!/bin/bash

./frp/frps -c ./frp/frps.ini &
gunicorn app:app