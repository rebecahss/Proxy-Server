#Servidor
import socket
import sys
import os
import os.path
import datetime
from _thread import start_new_thread

IP = '127.0.0.1'
Porta = 8088
buffer_size = 8192

def getdenypage(permission):
	if permission == 0:
		arqdenypage = open("blacklistpage","r")
	else:
		arqdenypage = open("deny_terms_page","r")
	pagedeny = arqdenypage.read()
	pagedenybyte = pagedeny.encode('utf-8')
	arqdenypage.close()
	return pagedenybyte

def finddeny_terms (data):
										#Converte a variavel data em string
	datastr = data.decode("utf-8")
										#Abre o arquivo de deny_terms
	arqdeny = open("deny_terms","r")
	deny_term = arqdeny.readlines()
										#Inicializa a variável de retorno sinalizando que nenhum deny_term foi encontrado
	founded = 0
										#Busca todos os termos dentro do arquivo
	for line in deny_term:
										#Isola o termo a ser buscado
		term = line.split('\n')
										#Procura o termo no pacote de dados recebido/enviado
		achou = datastr.find(term[0])
		if achou == -1:							#Não encontrou o termo
			founded = 0
		else:								#Termo encontrado no pacote
			print('Termo encontrado:', term[0])
			founded = 1
			arqdeny.close()
			return founded
										#Caso após a consulta de todos os deny_terms nenhum seja encontrado, retorna 0 
	arqdeny.close()
	return founded

def geralog(webserver, permission, data):
	#Gera registro no arquivo de logs
	arqlog = open("logs","a")
	timenow = datetime.datetime.now()
	arqlog.write(timenow.strftime("%x"))
	arqlog.write(' ')
	arqlog.write(timenow.strftime("%X"))
	arqlog.write(' _ ')
	arqlog.write(' Acesso ')
	if permission == 0:
		arqlog.write('bloqueado _ URL presente na blacklist:\t')
		
	if permission == 1:
		arqlog.write('permitido _ URL presente na whitelist:\t')
		
	if permission == 2:
		arqlog.write('permitido _ Mensagem sem deny_terms\t\t\t')
		
	if permission == 3:
		arqlog.write('bloqueado _ Requisição contém deny_terms\t')

	if permission == 4:
		arqlog.write('bloqueado _ Página requisitada contém deny_terms\t')
		
	arqlog.write(webserver)
	arqlog.write('\n')
	arqlog.close()


def proxy(webserver, port, conn, addr, data, permission):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((webserver, port))
		s.sendall(data)
		
		while 1:
			reply = s.recv(buffer_size)
			if (len(reply)> 0):
				founded_reply = finddeny_terms(reply)
				if founded_reply == 1:
					permission = 4
					geralog(webserver, permission, data)
					replydeny = getdenypage(permission)
					conn.send(replydeny)
				else:
					geralog(webserver, permission, data)
					conn.send(reply)
				
			else:
				break

		s.close()

		conn.close()

	except socket.error (value, massage):
		print("erro proxy")
		s.close()
		conn.close()
		sys.exit(1)

def checksite (url):
	ret = 2
	arq = open('blacklist','r')
	datafile = arq.readlines()

	for line in datafile:
		if line == url:
			ret = 0
	arq.close()
	
	arq = open('whitelist','r')
	datafile = arq.readlines()

	for line in datafile:
		if line == url:
			ret = 1
	arq.close()
	

	return ret





def conn_cliente(conn, data, addr):

	try:
		data2 = data.decode("utf-8")
		first_line = data2.split('\n')[0]
		url = first_line.split(' ')[1]
		http_position = url.find("://")

		if (http_position == -1):
			temp = url
		else:
			temp =url[(http_position+3):]

		port_position = temp.find(":")
		webserver_position = temp.find("/")
		
		if webserver_position == -1:
			webserver_position =len(temp)
		webserver = ""
		port = -1

		if (port_position == -1 or webserver_position < port_position):
			port = 80
			webserver = temp[:webserver_position]
		else:

			port = int((temp[(port_position+1):])[:webserver_position - port_position -1])
			webserver = temp[:port_position]

		permission = checksite(webserver+'\n')
		if permission == 0: 									#Destino contido na blacklist
			geralog(webserver, permission, data)
			replydeny = getdenypage(permission)
			conn.send(replydeny)
			conn.close()
			
		else: 											#Caso não contido na blacklist
			if permission == 2: 								#Busca termos proibidos
				founded = finddeny_terms(data)
				if founded == 1:							#Termo proibido encontrado
					permission = 3 							#Muda a permissão para 3 (termo proibido encontrado)
					print('Request with deny_terms')
					geralog(webserver, permission, data)				#Gera log de requisição bloqueada por conter termos proibidos
					conn.close()							#Descarta requisição com termo proibido
				else:
					proxy(webserver, port, conn, addr, data, permission)		#Encaminha requisição sem termos proibidos
			else: 										#Destino contido na whitelist
				proxy(webserver, port, conn, addr, data, permission)
		

	except Exception:
		pass


def main():

	# Create a TCP socket
	try:
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.bind((IP,Porta))
		server.listen(10)
		print ("Escutanto com" ,IP,Porta)

	except Exception as erro:
		print('Deu ruim')
		print (erro)
		server.close()

	while 1:
		try:
			conn, addr_client = server.accept()
			data = conn.recv(buffer_size)
			start_new_thread(conn_cliente, (conn, data,addr_client))

		except KeyboardInterrupt:
			server.close()
			sys.exit(1)

	server.close()



#Começo2
main()





																																																																																																																																																																																																																																																																																																																																																																																																																																															
