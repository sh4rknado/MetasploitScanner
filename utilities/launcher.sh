#!/bin/bash

msfconsole -x "load msgrpc Pass=zerocool"
msfrpcd -P zerocool  -S
