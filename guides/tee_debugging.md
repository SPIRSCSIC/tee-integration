## Pasos para depurar en TEE

1. Compilamos con el flag `-DCMAKE_BUILD_TYPE=Debug`
   ```bash
   $ cmake -B build -DCMAKE_BUILD_TYPE=Debug && make -C build
   ```

2. Iniciamos el qemu en modo depuración (de ahora en adelante **#term1**).
   Esperamos que aparezca el banner que nos indica que podemos conectarnos a través de `gdb`
   antes de continuar con el siguiente paso
   ```bash
   $ make -C build -j image && make -C build -j debug
   ...
   ...
   **** Running QEMU SSH on port 7777 ****
   **** GDB port 7778 ****
   ```

3. Abrimos otra terminal (de ahora en adelante **#term2**) y conectamos al contenedor
   del TEE. Ejecutamos el script `debug.sh`, presionamos `Enter` dos veces,
   cuando cargue la shell escribimos `c` y presionamos `Enter` de nuevo.
   ```bash
   $ docker exec -it spirs bash
   root@41635f7065f5:/spirs_tee_sdk# ./debug.sh
   GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1
   Copyright (C) 2022 Free Software Foundation, Inc.
   License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
   This is free software: you are free to change and redistribute it.
   There is NO WARRANTY, to the extent permitted by law.
   Type "show copying" and "show warranty" for details.
   This GDB was configured as "x86_64-linux-gnu".
   Type "show configuration" for configuration details.
   For bug reporting instructions, please see:
   <https://www.gnu.org/software/gdb/bugs/>.
   Find the GDB manual and other documentation resources online at:
       <http://www.gnu.org/software/gdb/documentation/>.

   For help, type "help".
   Type "apropos word" to search for commands related to "word"...
   Reading symbols from /keystone/build/linux.build/vmlinux...
   (No debugging symbols found in /keystone/build/linux.build/vmlinux)
   Remote debugging using localhost:3182
   0x0000000000001000 in ?? ()
   --Type <RET> for more, q to quit, c to continue without paging--
   <Enter>
   add symbol table from file "build/tee_demos"
   Reading symbols from build/tee_demos...
   add symbol table from file "build/eyrie-rt"
   Reading symbols from build/eyrie-rt...
   (gdb) c
   Continuing.
   ```

4. Volvemos a **#term1** y esperamos que cargue. Iniciamos sesión con las credenciales
   `root:sifive`.
   ```bash
       OpenSBI v1.1
      ____                    _____ ____ _____
     / __ \                  / ____|  _ \_   _|
    | |  | |_ __   ___ _ __ | (___ | |_) || |
    | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
    | |__| | |_) |  __/ | | |____) | |_) || |_
     \____/| .__/ \___|_| |_|_____/|____/_____|
           | |
           |_|

   [SM] Initializing ... hart [0]
   [SM] Keystone security monitor has been initialized!
   a41b1ad4905ceeea15e21b1f6472327596a45ac698001e7ccc9edf47bc9a29bf541edcf201e4e57ebe6643bb940ec748cf266f518b43499b695c1e93d0173e39
   ...
   ```

5. Volvemos a **#term2** y enviamos la combinación de teclas `Ctrl+C`. Ponemos un breakpoint
   donde queramos pararnos y volvemos a continuar la ejecución
   ```bash
   (gdb) c
   Continuing.
   (gdb) ^C
   Program received signal SIGINT, Interrupt.
   0xffffffff80003566 in arch_cpu_idle ()
   (gdb) break groupsig_init
   Breakpoint 1 at 0x5adc4: file /spirs_tee_sdk/modules/libgroupsig/src/groupsig/groupsig.c, line 118.
   (gdb) c
   Continuing.
   ```

6. Volvemos a **#term1**, cargamos el módulo de keystone y ejecutamos `tee_demos.ke`. La ejecución
   continuará y se parará donde declaramos el breakpoint
   ```bash
   # insmod keystone-driver.ko
   [   36.580742] keystone_driver: loading out-of-tree module taints kernel.
   [   36.618030] keystone_enclave: keystone enclave v1.0.0
   # ./tee_demos.ke ps16
   # ./tee_demos.ke ps16
   Verifying archive integrity... All good.
   Uncompressing Keystone Enclave Package
   ##### Testing OpenSSL randomness
   Iteration[0] rc: 1 BIGNUM: 845
   Iteration[1] rc: 1 BIGNUM: 509
   Iteration[2] rc: 1 BIGNUM: 387
   Iteration[3] rc: 1 BIGNUM: 76
   Iteration[4] rc: 1 BIGNUM: 532

   ##### Testing groupsig_init

   ```

7. Volvemos a **#term2** para depurar desde el breakpoint
   ```bash
   Breakpoint 1, groupsig_init (code=4 '\004', seed=13949) at /spirs_tee_sdk/modules/libgroupsig/src/groupsig/groupsig.c:118
   118       if(!(gs = groupsig_get_groupsig_from_code(code))) {
   (gdb) n
   123       if(!(sysenv = sysenv_init(seed))) {
   (gdb) n
   128       return gs->init();
   (gdb) n
   130     }
   (gdb)
   ps16_test () at /spirs_tee_sdk/modules/libgroupsig/tests/ps16.c:17
   17        end = clock();
   (gdb)
   18        print_exp_rc("", rc);
   (gdb)
   ```
