# lms_operator_lkm

A Linux Kernel Module (LKM LSM) that demonstrates how to make an LKM non-removable and discusses the complexity of enforcing user creation policies at the kernel level. This module is designed to restrict user creation, allowing only the user `operator` to be created.


## Compilation
```sh
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

## Installation
```sh
insmod lms_operator_lkm.ko
```
- Attempting to remove with `rmmod` will fail.
