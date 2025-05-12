#!/bin/bash

chmod +x frp/frps
frp/frps -c frp/frps.ini &
gunicorn --timeout 60 app:app