
<p align="center">
  <img src="https://i.postimg.cc/2SXnczcf/sabueso-logo.png" alt="Logo del proyecto" width="600">
</p>


# Sabueso

## Descripción

`Sabueso-Mitm` es un experimento de _Man-in-the-Middle_ (MITM) para interceptar tráfico HTTP y HTTPS entre dos dispositivos en la misma red.  
Su objetivo es puramente experimental y de curiosidad; **NO me hago responsable de malos usos.**

Hacer esto en una red que no te pertenece es **ILEGAL** y podria traerte consecuencias legales

---

## ¿que devuelve como output exactamente?

- **HTTPS** 

devuelve la ips con las que se interactuó:
- ip de la victima junto con la ip del sitio web visitado

esto nos podría servir para deducir por donde esta navegando la victima pero si la ip del sitio esta protegida por algun servicio como cloudflare, no podremos saber con exactitud a que sito pertenece

- **HTTP** 

esto es mas interesante: puesto que la informacion en este protocolo no viaja cifrada, si el usuario ingresa a sitios con este protocolo podriamos capturar formularios como contraseñas ... ⚠️ MUY PELIGROSO

## Características

- Ataque ARP-MITM entre dos máquinas objetivo.
- Sniffing de paquetes HTTP (puerto 80) y HTTPS (puerto 443).
- Opción para guardar info de paquetes HTTPS en archivo `.txt`.
- Limpia automáticamente las reglas de `iptables` al cerrar (`Ctrl+C`).

---

## Requisitos

- **S.O.:** Linux (solo kernels compatibles).  
- **Permisos:** Debe ejecutarse como **root** (o con `sudo`).  
- **Python 3.8+**  
- Librerías Python:
  ```bash
  pip install scapy colorama

## Instalacion

Clona este repo:

```
  git clone https://github.com/Urban20/Sabueso-Mitm.git

  cd Sabueso-Mitm
```
instala las dependencias:

`pip install -r requirements.txt`

---

## Paramatros

```
-h : muestra panel de ayuda

-m1, --maq1 : IP del dispositivo objetivo 1.

-m2, --maq2 : IP del dispositivo objetivo 2.

-if, --interfaz : (opcional) interfaz para habilitar sniffing.

-sf, --sniff : activa modo mitm + sniffing; sin este flag, solo MITM.

-db, --debug : si se produjo un error, crea un archivo con dicho error
```
Ejemplos:
---
### SOLO MITM

Podriamos utilizar esto para simplemente interponernos entre dos maquinas o entre una maquina y el router (esto ultimo deja la maquina sin internet porque por defecto la maquina que intercepta descarta los paquetes, por ende nunca llegan a router)

`sudo python3 mitm.py -m1 192.168.0.10 -m2 192.168.0.1`

---

### MITM + SNIFFING

Podriamos utilizar esto para interponernos entre dos maquinas o entre una maquina y el router.
En este ultimo caso la maquina que intercepta (maquina atacante) deberia actuar como proxy entre el router y la victima y mostrar en consola el trafico con los protocolos mencionados 

`sudo python3 mitm.py -m1 192.168.0.10 -m2 192.168.0.1 -if eth0 -sf`

## Autor:
Urb@n 