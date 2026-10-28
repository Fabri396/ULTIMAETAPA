# TicAmazon: TLS distribuido en C++11

No se necesita Python. `TLSManager.cc` usa OpenSSL y se compila como `TLSManager.out`. `start-bodega.sh` es un lanzador Bash pequeño; la lógica de generación, firma, validación y registro TLS está implementada en C++.

## 0. Seguridad y migración

**No publicar jamás** `.tls-private/`, `certs/*.key`, `certs/server.crt`, `certs/SI-*.crt`, tokens, inventarios ni bitácoras. Publicar únicamente `certs/siqp-trust.crt` (CA pública) y los fuentes. Si ya subiste claves a GitHub, considera esas claves comprometidas: genera nuevas, retíralas del seguimiento y limpia el historial antes de volver público el repositorio. `.gitignore` no borra el historial.

Antes de migrar, respalda `certs/`, `.dat` y logs. **Detén intermediario y bodegas.** La migración sustituye la CA antigua y exige distribuir la nueva CA pública a todas las máquinas. Ejecuta `init --migrate` una sola vez en la computadora administradora; nunca en las bodegas. Mantén `.tls-private/ca.key` exclusivamente en la administradora y protégela.

## 1. En la máquina intermediaria WS-05

```bash
make clean && make
./TLSManager.out init --migrate
./TLSManager.out serve --port 9443
```

En otra terminal:

```bash
./Intermediario.out
```

Si no existían certificados previos, usa `./TLSManager.out init` (sin `--migrate`). Si ya existe `.tls-private/ca.key`, NO vuelvas a ejecutar init: conserva la CA existente.

Abrir TCP 9443 (incorporación), 2027 (SIQP) y 8081 (web), según firewall de la red. No expongas 9443 a Internet; limita su acceso a la red de laboratorio.

**Distribución de CA:** copia `certs/siqp-trust.crt` a las bodegas. Puede versionarse en el repositorio si no contiene datos secretos. La autenticidad de esta CA debe confirmarse por un canal confiable (p. ej., huella SHA-256 comprobada con el administrador); no confíes ciegamente en una CA descargada de una fuente desconocida.

## 2. Autorizar una nueva bodega

En WS-05:

```bash
./TLSManager.out issue --id SI-01
```

Se emite un token aleatorio válido por 15 minutos y de un solo uso. Entregarlo de forma privada a quien inicia esa bodega; no subirlo a GitHub.

## 3. En la máquina de bodega WS-06

```bash
make clean && make
./start-bodega.sh --id SI-01 --intermediario 10.1.35.5:2027 --port 2028
```

En el primer inicio solicita el token. Se conecta a `10.1.35.5:9443` y verifica que el certificado del intermediario corresponda a `INT-01`. Genera una clave privada local y recibe el certificado `SI-01` firmado por la CA. En inicios siguientes conserva su identidad y no solicita otro token. La bodega anuncia su IP local automáticamente; si la máquina tiene varias redes o NAT, se puede indicar `--host IP_VISIBLE`.

Para SI-02, SI-03, ... SI-13, repetir `issue` con ID diferente y ejecutar el lanzador en la computadora correspondiente. **El puerto 2028 puede repetirse en computadoras distintas**; para múltiples bodegas en una sola máquina usar puertos distintos.

Si cambia la IP del intermediario, hay que proporcionar su nueva dirección o un nombre DNS que la resuelva. **TLS no depende de la IP para verificar identidades**, pero TCP sí necesita una dirección alcanzable. Los certificados de bodegas duran 90 días: esta versión no implementa renovación automática ni revocación; al expirar se necesita una renovación controlada.

## 4. Git

Antes de `git add`, revisar:

```bash
git status --short
git ls-files certs .tls-private
```

Si hay claves o certificados de servidores rastreados:

```bash
git rm --cached --ignore-unmatch certs/server.key certs/server.crt
```

No publiques la clave CA ni la clave privada de ninguna bodega. Si el repositorio ya tenía claves privadas en commits anteriores, eliminarlas de la versión actual **no elimina esas claves del historial**; revócalas/rota la CA y reescribe el historial antes de hacer público el repositorio.

## 5. Prueba local efectuada

Se compiló `make clean && make` sobre la versión suministrada de ULTIMAETAPA. Se probó `TLSManager.out init`, `issue`, `serve`, `enroll`, verificación X.509 y arranque de `Intermediario.out` + `ThreadMirrorServer.out` con identidad SI-01. Resultado: `[SI-01] Registro actualizado` y `[INT-01] Bodega registrada: SI-01`. **No se ha probado en las cuatro computadoras físicas**.

## Límites de esta versión

- El servicio de incorporación debe mantenerse en WS-05 cuando se vayan a incorporar bodegas.
- La CA y los tokens están administrados localmente por `TLSManager.out` en WS-05; no hay renovación/revocación automatizada ni alta sin autorización.
- Las identidades deben ser únicas. Si se copian claves privadas entre máquinas, la unicidad deja de estar garantizada.
- La validación del registro SIQP usa el certificado de la bodega. Los comandos administrativos existentes pueden requerir controles de autorización adicionales según el despliegue.
