'''
>git clone https://github.com/smicallef/spiderfoot
>cd spiderfoot
>pip install -r requirements.txt

Iniciar la herramienta con el siguiente comando:

>python sf.py -l 0.0.0.0:5000


Dentro del proyecto, es recomendable ver el directorio donde están las pruebas unitarias. Ayudan a entender mejor la API.
El funcionamiento general de este script es el siguiente:

0. Este script debe estar ubicado en el directorio donde se encuentra el proyecto de SpiderFoot
1. Se define un diccionario con todas las opciones por defecto. Este elemento se crea como un atributo de la clase SpiderFootManager y se inicializa en el constructor
2. Una vez introducido el objetivo, se procede a cargar los módulos de SpiderFoot, los cuales son ficheros PY ubicados en el directorio «modules».
3. Se establece la API Key de Shodan en el script, la cual luego será asignada al módulo «sfp_shodan»
4. La carga de módulos se puede realizar desde los métodos «searchByUseCase», que devuelve los métodos por caso de uso y «searchAllModules» que los devuelve todos.
5. Se inicia el escaneo con el objetivo, tipo y modulos cargados.
6. El escaneo y los resultados aparecerán en la consola web de SpiderFoot una vez se ejecute este script.  
'''

from sfscan import SpiderFootScanner
from spiderfoot import SpiderFootHelpers
from sflib import SpiderFoot
from spiderfoot import SpiderFootDb

import uuid
import os 

class SpiderFootManager:
	def __init__(self):
		self.default_options = {
			'_debug': False,
			'__logging': True,  # Logging in general
			'__outputfilter': None,  # Event types to filter from modules' output
			'_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',  # User-Agent to use for HTTP requests
			'_dnsserver': '',  # Override the default resolver
			'_fetchtimeout': 5,  # number of seconds before giving up on a fetch
			'_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
			'_internettlds_cache': 72,
			'_genericusers': ",".join(SpiderFootHelpers.usernamesFromWordlists(['generic-usernames'])),
			#'__database': f"{SpiderFootHelpers.dataPath()}/spiderfoot.test.db",  # Base de datos de pruebas. La BBDD de SF está en la línea de abajo, así se podrá ver el escaneo creado en la consola web
			'__database': f"{SpiderFootHelpers.dataPath()}/spiderfoot.db",  # note: test database file
			'__modules__': None,  # List of modules. Will be set after start-up.
			'__correlationrules__': {},  # List of correlation rules. Will be set after start-up.
			'_socks1type': '',
			'_socks2addr': '',
			'_socks3port': '',
			'_socks4user': '',
			'_socks5pwd': '',
			'__logstdout': False
		}
		self.sfscan = None
		self.shodanKey = None
	
	def __printModule(self, sfModule):
		print("Nombre: {0} ".format(sfModule.get("name")))
		print("Descripción: {0} ".format(sfModule.get("descr")))
		print("Categorías: {0} ".format(sfModule.get("cats")))
		print("Casos de usos: {0} \n".format(sfModule.get("group")))

	def __loadModules(self):
		mod_dir = os.path.dirname(os.path.abspath(__file__)) + '/modules/'
		sfModules = SpiderFootHelpers.loadModulesAsDict(mod_dir, ['sfp_template.py'])
		for module in sfModules:
			if module == "sfp_shodan" and self.shodanKey is not None:
				sfModules[module].get("opts")['api_key'] = self.shodanKey
		return sfModules


	def searchAllModules(self):
		sfModules = self.__loadModules()
		print("Información de los módulos cargados: ")
		for module in sfModules:
			self.__printModule(sfModules[module])
		return sfModules

	#Los posibles casos de uso son Passive, Footprint e Investigate
	def searchByUseCase(self, useCase):
		sfModules = self.searchAllModules()
		modulesByUseCase = {}
		for module in sfModules:
			if useCase in sfModules[module].get("group"):
				self.__printModule(sfModules[module])
				modulesByUseCase[module] = sfModules[module] 
		return modulesByUseCase

	'''El constructor de la clase SpiderFootScanner tiene la siguiente firma:
			__init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
	El tipo de target puede ser: 
			'IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'INTERNET_NAME',
			'EMAILADDR', 'HUMAN_NAME', 'BGP_AS_OWNER', 'PHONE_NUMBER', "USERNAME" y 'BITCOIN_ADDRESS'
	'''
	def runScan(self, target, modules):
		scan_id = SpiderFootHelpers.genScanInstanceId()
		self.default_options['__modules__'] = modules
		sfscan = SpiderFootScanner("Escaneo de un dominio", scan_id, target, "INTERNET_NAME", list(modules.keys()), self.default_options, start=True)
		#sfscan = SpiderFootScanner("Escaneo de una IP", scan_id, target, "IP_ADDRESS", list(modules.keys()), self.default_options, start=True)
		print("Escaneo creado con identificador {0} ".format(scan_id))
		print("Estado del escaneo {0}".format(sfscan.status))

manager  = SpiderFootManager()
target = input("Introduce el objetivo: ")
#manager.shodanKey=None
manager.shodanKey="zqLmHqEJuGTqkSq1NtzsdwpPYITjO70e"
#modules = manager.searchByUseCase("Footprint")
modules = manager.searchAllModules()
manager.runScan(target, modules)

