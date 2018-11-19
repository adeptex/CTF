#!/bin/bash
#
# $1 = target

curl -s $1 -o /dev/null -w "\
time_namelookup:    %{time_namelookup}\n\
time_connect:       %{time_connect}\n\
time_appconnect:    %{time_appconnect}\n\
time_pretransfer:   %{time_pretransfer}\n\
time_redirect:      %{time_redirect}\n\
time_starttransfer: %{time_starttransfer}\n\
-------------------------\n\
time_total:         %{time_total}\n\n"
