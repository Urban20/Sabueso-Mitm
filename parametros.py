# argumentos que utiliza el programa

import argparse


arg = argparse.ArgumentParser(usage="sabueso es una herramienta experimental que intercepta comunicaciones de protocolos HTTP y HTTPS (sniffing), ademas hace ataques mitm")
arg.add_argument("-m1","--maq1",type=str,help="dispositivo objetivo nro 1")
arg.add_argument("-m2","--maq2",type=str,help="dispositivo objetivo nro 2")
arg.add_argument("-if","--interfaz",type=str,help="interfaz de red a utilizar (necesario para el sniffing)")
arg.add_argument("-sf","--sniff",action=argparse.BooleanOptionalAction,help="habilita el sniffing entre los dispositivos afectados")
param = arg.parse_args()

