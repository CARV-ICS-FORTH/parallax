#!/bin/python

#hosts=['tie4.cluster.ics.forth.gr-8080', 'tie3.cluster.ics.forth.gr-8080', 'tie2.cluster.ics.forth.gr-8080', 'sith5.cluster.ics.forth.gr-8080', 'sith4-8080']
hosts=['tie4.cluster.ics.forth.gr-8080']


print('0 -oo 04000 tie4.cluster.ics.forth.gr-8080')
region_id=1
idx = 0
min = 4000
for x in range(8000, 99000, 4000):
  if idx >= len(hosts):
    idx = 0
  min = str(min)
  if(len(min) < 5):
   a = int(5-len(min))
   for i in range(a):
     min = '0'+min
  max = str(x)
  if(len(max) < 5):
   a = int(5-len(max))
   for i in range(a):
     max = '0'+max
  print(str(region_id)+'  '+' '+min+' '+max+' '+hosts[idx])
  idx = idx + 1
  min = x
  region_id = region_id + 1

idx = idx+1
if idx >= 1:
  idx = 0

print(str(region_id)+'  '+' '+str(min)+'  +oo'+' '+hosts[idx])
