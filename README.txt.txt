------------------------------README FILE---------------------------------

:::Herramienta de ciberseguridad:::
HERRAMIENTA/ATAQUE DE ENVENENAMIENTO DE TABLAS ARP PARA REDES LAN

Este proyecto tiene como finalidad codificar las tablas ARP dentro de dos maquinas conectadas a una misma red LAN

---Utiliza la libreria Scapy para manejar los paquetes de la red y llegar al objetivo de poder vizualizar los paquetes enviados en a travez de la red.

---Utiliza otros modulos como argparser para mostrar ayuda de los parametros y su correcto funcionamiento.
---Esta herramienta está disponible para Python 3

---A la hora de ejecutarse la funcion poison, desencadena algunos eventos como la conexión a una API de mensajeria, Twilio, y alerta a la hora que se detiene la ejecución del script, modificar los parametros dentro de keys.py para ingresar tus tokens de validación de y autenticación de la cuenta Twilio.

---La herramienta recibe los parametros -h: Solo para mostrar la ayuda de la correcta ejecución del programa, recibe la ip de la victima como primer parametro, la puerta de enlace predeterminada de la maquina que ejecuta el ataque, y la interface de la tarjeta de red, en linux es eth0 por defecto

Ejemplo de uso: sudo, python envenenamiento.py 192.168.0.10  192.168.1.1  eth0

---El script creará una carpeta que contendrá el archivo Output.txt con un reporte de la ejecución del programa, y dicho reporte será enviado a travez de correo electroico que previamente está configurado dentro de mi maquina linux


