
[![image.png](https://i.postimg.cc/ZqBDfbnL/image.png)](https://postimg.cc/Jy8q0Wby)

> [!IMPORTANT]
La herramienta puede debilitar o tirar la conexion de la maquina victima, ademas, el sitema de la victima podria avisarle que se esta llevando a cabo un ataque

¿que es un ataque mitm?
ataque mitm : ataque de "hombre en el medio" o "man in the middle"

Es un tipo de ciberataque el cual nos permite interponernos entre dos computadoras e interceptar trafico que no nos corresponde o hacernos pasar por un dispositivos que no somos. Hay varias formas de emplear un ataque mitm, en este caso es una de tipo arp spoofing (suplantacion de identidad en la tabla arp, la cual es una lista que asocia las direcciones ip de los dispositivos con sus direcciones mac), el cual nos hacemos pasar por un dispositivo que realmente no somos modificando dicha tabla asociando nuestra ip con la direccion mac de la victima

           [ Máquina 1 ]                       [ Máquina 2 ]
                |                                  |
     (Intercepción y manipulación)        (Intercepción y manipulación)
                |                                  |
               \|/                                \|/
             +-----------------------------------------+
             |                Atacante                  |
             | (Intercambia y manipula datos entre ambos)|
             +-----------------------------------------+



### Descripcion:

Este codigo automatiza un ataque de hombre en el medio usando scapy con el objetivo de interceptar paquetes relacionados a protocolos http y https cuyo fin es la obtencion de informacion de los sitios con los que interactuan las maquinas afectadas

El script efectua un ataque mitm y posteriormente olfatea o sniffea la red en busca de informacion

Lo que se obtiene son nombres de host o direcciones ip, con esas direcciones se podria recopilar informacion para saber por donde estuvo navegando la victima

Si el host esta protegido por algun servicio como Cloudflare, no se podra saber con certeza a que sitio web pertenece la ip ya que se estaria ocultando la ip verdadera del sitio

> [!WARNING]
--> No me hago responsable del mal uso que se le pueda dar a este codigo. El codigo fue hecho con fines de experimentacion y uso personal , puede fallar y/o tener errores

autor: urb@n
