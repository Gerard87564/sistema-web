#!/bin/bash

frp/frps.exe -c frp/frps.ini &
gunicorn app:app