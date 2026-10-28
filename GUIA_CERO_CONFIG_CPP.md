# TicAmazon: alta automatica C++ (modo laboratorio)

## Resumen
La nueva bodega **no necesita introducir IP, token ni certificados**. `ThreadMirrorServer.out` descubre el intermediario usando broadcast UDP, instala la CA publica en el primer contacto y solicita su propio certificado con OpenSSL. El intermediario inicia automaticamente la CA local (si no existe) y el servicio TLS de altas.

**Aviso importante: el descubrimiento inicial no esta autenticado** (Trust on First Use, TOFU) y el alta admite automaticamente cualquier equipo que alcance el puerto 9443. Un equipo malicioso en la LAN puede suplantar el descubrimiento, crear bodegas o usar IDs ajenos. Esta configuracion solo es aceptable para una practica en **red local aislada y de confianza**, no para produccion. TLS protege el trafico una vez establecida la confianza, pero no autentica al primer intermediario encontrado. Para una red insegura se exige una raiz confiable precargada o autorizacion previa de equipos.

## Archivos modificados
- `AutoDiscovery.h` (nuevo): servidor y cliente UDP 2026, deteccion de IP origen y descarga de CA publica por respuesta de descubrimiento.
- `TLSManager.cc`: incorporacion automatica sin token en modo laboratorio y creacion local de claves C++/OpenSSL.
- `Intermediario.cc`: inicializa la CA una sola vez, abre el servicio TLS 9443 y anuncia el intermediario por UDP.
- `ThreadMirrorServer.cc`: descubre, comprueba la CA y se inscribe sin necesitar ejecutables auxiliares manuales. Archivo de inventario por defecto `SI-XX.dat`.
- `Makefile`: enlace y dependencias.

## Instalar
1. Respaldar `certs/`, `.tls-private/`, los `*.dat` y logs antes de migrar.
2. Colocar los archivos del paquete en la raiz del repositorio, encima de los anteriores.
3. Compilar: `make clean && make`.
4. Iniciar **solo un** intermediario: `./Intermediario.out` en WS-05. El mismo ejecutable arranca la autoridad certificadora y servicio de alta automaticamente. En primeros inicios antiguos crea un respaldo de certificados; nunca regenera una CA que ya tenga `.tls-private/ca.key`.
5. En WS-06 (mismo repositorio actualizado): `./ThreadMirrorServer.out --id SI-01 --port 2028`. No se necesita `--intermediario` ni `--host`.
6. Para SI-02: `./ThreadMirrorServer.out --id SI-02 --port 2029`; para SI-03 en otro PC: `./ThreadMirrorServer.out --id SI-03 --port 2028` (mismo puerto se permite en equipos distintos).
7. Ejecutar `./WebServer.out` donde corresponda (WS-05) para mantener el panel en puerto 8081.

## Red
- UDP 2026: solicitud y respuesta de descubrimiento (broadcast en la misma subred).
- TCP 2027: servicio SIQP/TLS del intermediario.
- TCP 9443: inscripcion automatica TLS.
- TCP 2028 y sucesivos: cada bodega debe ser accesible desde el intermediario para consultas/compras.
- 8081/8082: web/API existente.

Si un switch o la red separa los equipos en VLAN/subredes distintas, el broadcast no atraviesa el router normalmente. Se requiere configurar un mecanismo de descubrimiento entre VLAN (DNS-SD/retransmisor) o pasar `--intermediario host:puerto` y distribuir la CA publica de una manera confiable. En Fedora, `firewalld` puede bloquear UDP 2026, TCP 9443 y los puertos de bodegas: comprobar las reglas con el administrador del laboratorio. No hay garantía de descubrimiento en cualquier red del mundo.

## Identidades y repositorio
- La clave de CA `.tls-private/ca.key` **solo** debe permanecer en el intermediario.
- `certs/SI-XX.key` se crea por equipo y nunca se sube al repositorio.
- No compartir `.tls-private/`, `certs/*.key`, los `certs/SI-XX.crt`, los inventarios `.dat` ni los logs por Git.
- La version original incluia potencialmente `certs/server.key` rastreado por Git: retirarlo del indice, rotar esa clave y revisar el historial. `.gitignore` no borra secretos ya publicados.
- IDs deben ser unicos: en modo de laboratorio se aceptan altas sin autenticacion individual y **no se impide que otra maquina solicite el mismo ID**; es un limite de seguridad explicitamente reconocido.

## Que se verifico
- `make -j4` compilo sin errores.
- Arranque automatico del intermediario, CA y descubridor.
- Alta TLS automatica de SI-01 y SI-02 en procesos diferentes, ambas registradas y con respuestas tipo 41, usando interfaces de la misma maquina de pruebas.
- No se pudo verificar la conectividad real entre WS-05, WS-06, WS-07 y WS-08: probar en Fedora y con el firewall del laboratorio.
