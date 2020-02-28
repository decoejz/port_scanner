import tkinter as tk
import tkinter.scrolledtext as tkst
import portscanner as ps
import json

class BoardScanner:

    def __init__(self):
        #Criando a janela gráfica e suas diretrizes
        self.window = tk.Tk()
        self.window.title('Port Scanner')
        self.window.geometry("690x700+600+55")
        
        # Criando as linhas e colunas do jogo
        self.window.rowconfigure(0, minsize=20, weight=1)
        self.window.rowconfigure(1, minsize=90, weight=1)
        self.window.rowconfigure(2, minsize=90, weight=1)
        self.window.rowconfigure(3, minsize=90, weight=1)
        self.window.rowconfigure(4, minsize=90, weight=1)
        self.window.rowconfigure(5, minsize=90, weight=1)
        self.window.rowconfigure(6, minsize=200, weight=1)
        self.window.rowconfigure(7, minsize=20, weight=1)
        
        self.window.columnconfigure(0, minsize=20, weight=1)
        self.window.columnconfigure(1, minsize=100, weight=1)
        self.window.columnconfigure(2, minsize=100, weight=1)
        self.window.columnconfigure(3, minsize=20, weight=1)

        self.window.resizable(width=False, height=False)

        # Rede
        ## Label
        rede = tk.Label(self.window)
        rede.configure(text = "IP:")
        rede.grid(row=1, column=1, sticky='ew')
        ## Escrita
        exemplo_rede = tk.StringVar()
        exemplo_rede.set('192.168.50.93')
        self.entrada_rede = tk.Entry(self.window, textvariable = exemplo_rede)
        self.entrada_rede.grid(row=1, column=2, sticky="ew")

        # TCP/UDP
        self.tcp_value = tk.IntVar()
        self.tcp_box = tk.Checkbutton(self.window, text='TCP', onvalue = 1, offvalue = 0, variable=self.tcp_value)
        self.tcp_box.grid(row=2,column=1)
        self.tcp_box.select()
        self.udp_value = tk.IntVar()
        self.udp_box = tk.Checkbutton(self.window, text='UDP', onvalue = 1, offvalue = 0, variable=self.udp_value)
        self.udp_box.grid(row=2,column=2)

        # Portas
        ## Label
        ports = tk.Label(self.window)
        ports.configure(text = "Portas:")
        ports.grid(row=3, column=1, sticky='ew')
        ## Escrita
        exemplo_port = tk.StringVar()
        exemplo_port.set('0-65535')
        self.entrada_portas = tk.Entry(self.window, textvariable = exemplo_port)
        self.entrada_portas.grid(row=3, column=2, sticky="ew")
        self.entrada_portas.bind('<Return>',self.scaner_host)

        #Botoes
        self.scanhost = tk.Button(self.window, text="Escanear host")
        self.scanhost.grid(row=4,column=1, sticky='nsew', columnspan=1)
        self.scanhost.bind('<1>',self.scaner_host)

        self.scannet = tk.Button(self.window, text="Escanear rede")
        self.scannet.grid(row=4,column=2, sticky='nsew')
        self.scannet.bind('<1>',self.scaner_network)

        #Saida
        self.resposta = tkst.ScrolledText(self.window, wrap='word')
        self.resposta.grid(row=5, column=1, sticky='nsew', rowspan=2, columnspan=2)
        self.resposta.configure(font='Bodoni 10', bg='white')

        self.ps = ps.PortScanner()

        self.servico = {}
        with open("portas_servicos.json") as json_file:
            data = json.load(json_file)
            for p in data:
                self.servico[p] = data[p]

    def iniciar(self):
        self.window.mainloop()

    def scaner_host(self, event):
        self.resposta.delete(1.0,tk.END)
        #Prepara as informacoes para escanear as portas
        lista_portas = self.entrada_portas.get().split('-')
        if len(lista_portas) == 1 and lista_portas[0]=='':
            portasRange = [0,365535]
        elif len(lista_portas) == 1:
            portasRange = [int(lista_portas[0]),int(lista_portas[0])]
        else:
            portasRange = [int(lista_portas[0]),int(lista_portas[1])]

        tcp_list, udp_list = self.ps.scanPorts(self.entrada_rede.get(),portasRange,self.tcp_value.get(),self.udp_value.get())
        
        #Lista as portas TCP
        if (self.tcp_value.get() == 1):
            self.resposta.insert('insert', 'TCP:\n')
            for i in tcp_list:
                try:
                    self.resposta.insert('insert', '{0}/TCP open {1}\n'.format(i,self.servico[str(i)+'/tcp']))
                except:
                    self.resposta.insert('insert', '{0}/TCP open {1}\n'.format(i,'desconhecido'))

        #Lista as portas UDP
        if (self.udp_value.get() == 1):
            self.resposta.insert('insert', '\nUDP:\n')
            for i in udp_list:
                self.resposta.insert('insert', '{0}/UDP {1}\n'.format(i[0],i[1]))

    def scaner_network(self, event):
        self.resposta.delete(1.0,tk.END)
        rede = self.ps.scanNet(self.entrada_rede.get())
        self.resposta.insert('insert', 'IP         ----------         MAC\n')

        for maquina in rede:
            self.resposta.insert('insert', '{0}  ----  {1}\n'.format(maquina['ip'],maquina['mac']))

scanner = BoardScanner()
scanner.iniciar()