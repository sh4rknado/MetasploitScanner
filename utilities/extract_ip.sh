#!/usr/bin/bash


while read line; do
  ip="$(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <<< "$line")"
  echo "$ip"
done < $1 >> ip_list

sed -i '/^$/d' ip_list
sort -u ip_list >> ip_list2
mv ip_list2 ip_list
