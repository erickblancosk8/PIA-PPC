#!/bin/bash
cd REPORTES
echo "REVISA LA MAQUINA KALI, REPORTE DEL ATAQUE" | mutt -s "ALERTA! SE DETUVO EL ATAQUE" erick.sk8@live.com.mx -a Output.txt
