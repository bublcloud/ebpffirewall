# Bubl ebpf firewall

**Warning!** This is a work in progress and not recomended for producion use.
Example to create a data driven firewall.

## thanks 
Thanks for the great work of:
1. https://github.com/gamemann/XDP-Firewall
2. https://github.com/xdp-project/

# getting started

## install dependancies
Recomended way is to look at an existing tutorial to get started with ePBF/XDP

### example for ubuntu
```
sudo apt-get install libconfig-dev llvm clang libelf-dev build-essential -y
```

## clone this repo
```
cd ~/
git clone https://github.com/bublcloud/ebpffirewall.git
```

## get libpf repo redy
```
cd ~/
```

### libbpf from xdp project
```
git clone https://github.com/xdp-project/xdp-tutorial.git
cd ~/xdp-tutorial/
git submodule update --init
```

### make project
```
cd ~/xdp-tutorial/basic01-xdp-pass/
make
```

### copy to ebpf folder
```
cd ~/
cp -r ~/xdp-tutorial/libbpf ~/ebpffirewall/
cd ~/ebpffirewall/
```

## make project

### epbf programm
```
make
```

### loader
```
make loader
```

### command line utility
```
make fcmd
```