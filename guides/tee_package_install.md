## Pasos para añadir paquetes al entorno emulado (QEMU)

Los siguientes comandos deberán ejecutarse en el contenedor desde donde se
compila el QEMU.

1. Instalamos la siguiente librería, necesaria para abrir el configurador de buildroot:
   ```bash
   $ apt update && apt install libncurses-dev -y
   ```

2. Navegamos al siguiente directorio y ejecutamos el configurador
   ```bash
   $ cd /keystone/build/buildroot.build/
   $ make menuconfig
   ```

3. Seleccionamos lo siguiente (con barra espaciadora)
   ```
   Target packages --->
   Interpreter languages and scripting  --->
   python3
   core python3 modules ---> (usamos Enter)
   <Escoger los paquetes deseados>
   <Exit>
   External python modules
   <Escoger los paquetes deseados>
   <Save>
   <Exit>
   <Exit>
   ```

4. Editamos el fichero `.config`, incrementamos el tamaño del rootfs de `60M` a `200M`
   para que nos permita instalar los nuevos paquetes y recompilamos
   ```
   BR2_TARGET_ROOTFS_EXT2_SIZE="200M"
   ```
   ```bash
   $ make -s -j
   ```

5. Volvemos al directorio /spirs_tee_sdk/build y ejecutamos
   ```bash
   $ make -j qemu
   ```

6. Esperamos que cargue el QEMU y ya deberíamos tener acceso a python3
   ```bash
   # python3
   Python 3.10.6 (main, Aug 29 2023, 13:12:50) [GCC 11.2.0] on linux
   Type "help", "copyright", "credits" or "license" for more information.
   >>>
   ```
   ```bash
   # python3 -m http.server
   Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
   127.0.0.1 - - [01/Jan/1970 00:06:38] "GET / HTTP/1.1" 200 -
   ```
   ```bash
   # wget localhost:8000
   Connecting to localhost:8000 (127.0.0.1:8000)
   saving to 'index.html'
   index.html           100% |*******************************************************************************************************************************************************************|   448  0:00:00 ETA
   'index.html' saved
   ```
