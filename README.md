# core2elf64

```
install: python3 -m pip install -r requirements.txt

use: python3 core2elf64.py <corefile> <out_file>
```

## 如何获取最优的core文件

假设现在有一个用魔改upx加壳的程序。

我们先用gdb启动这个程序，可以使用catch捕捉一些程序经常会用到的syscall，如brk，mprotect等，
反正就是想办法让程序中断在upx解压后。

给目标程序设置coredump_filter：

```
echo 0x07 > /proc/<pid>/coredump_filter
```

在gdb中使用gcore 生成core文件。

使用脚本修复文件，当然，此次修复的文件大概率是没法用的。

不过修复时会打印出程序的OEP入口点
```
[*] found entry point: 0x00000000000241c0
[*] dynamic elf, base: 0x00007f758fb6c000
```

这样我们就可以删除之前的catch断点，转而给OEP设置硬件断点。
断在OEP后在使用gcore生成core文件。

再用脚本修复这个core文件，大概率就会修复的非常完美。