# Using FastMap

## Login in a machine that FastMap is available
```bash
ssh thegates

ssh sith6

sudo -i # Be extremely careful after you run this command as you become root and you could break the OS!

```

## Configuring FastMap
```bash
cd fastmap_apapag

vim driver/main.c
```

Search for the `perma_mmap_buf_size` variable and use one of the defines `PAGES_*G` where the star is replaced by the size of the memory allocation.

For example to allocate 192 Gigabytes using FastMap:

```C
static long perma_mmap_buf_size = PAGES_192G;
```

To apply the changes you made run:
```bash
make clean
make
```
Then open the `00_load-it-sith6.sh` script and change the `DEVICE` variable to the device you want to use.

For example if you want to use the `/dev/nvme0n1` device:

```bash
DEVICE=/dev/nvme0n1
```

## Loading FastMap

To load FastMap run:
```bash
./00_load-it-sith6.sh

```

# Running Parallax with FastMap

1. Find the`char * pathname` variable in `YCSB-CXX/db/eutropia_db.h` and set it to `/dev/dmap/dmap1`.

2. Enter the `build/YCSB-CXX` directory and create a script with the following contents:

```bash
#!/bin/bash

sudo chown $USER /dev/dmap/dmap1
sudo chown $USER /dev/nvme0n1
./mkfs.eutropia.single.sh /dev/nvme0n1 1 0
./ycsb-edb -threads 1 -dbnum 1 -e execution_plan.txt
```

To execute the script run:

```bash
chmod +x run.sh
./run.sh
```
