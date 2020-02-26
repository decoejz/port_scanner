import tkinter as tk
import tkinter.scrolledtext as tkst
import portscanner as ps

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
        exemplo_rede.set('192.168.1.93')
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
        exemplo_port.set('0-100')#('0-65535')
        self.entrada_portas = tk.Entry(self.window, textvariable = exemplo_port)
        self.entrada_portas.grid(row=3, column=2, sticky="ew")

        #Botoes
        self.scanhost = tk.Button(self.window, text="Escanear host")
        self.scanhost.grid(row=4,column=1, sticky='nsew', columnspan=2)
        self.scanhost.bind('<1>',self.scaner_host)

        # self.scannet = tk.Button(self.window, text="Escanear rede")
        # self.scannet.grid(row=4,column=2, sticky='nsew')
        # self.scannet.bind('<1>',self.scaner_network)

        #Saida
        self.resposta = tkst.ScrolledText(self.window, wrap='word')
        self.resposta.grid(row=5, column=1, sticky='nsew', rowspan=2, columnspan=2)
        self.resposta.configure(font='Bodoni 10', bg='white')

        self.ps = ps.PortScanner()

    def iniciar(self):
        self.window.mainloop()

    def scaner_host(self, event):
        lista_portas = self.entrada_portas.get().split('-')
        if len(lista_portas) == 1 and lista_portas[0]=='':
            portasRange = [0,365535]
        elif len(lista_portas) == 1:
            portasRange = [int(lista_portas[0]),int(lista_portas[0])]
        else:
            portasRange = [int(lista_portas[0]),int(lista_portas[1])]

        tcp_list, udp_list = self.ps.scanPorts(self.entrada_rede.get(),portasRange,self.tcp_value.get(),self.udp_value.get())
        resposta_text = ''
        if (self.tcp_value.get() == 1):
            resposta_text += 'TCP:\n'
            for i in tcp_list:
                resposta_text += '{0}/TCP open\n'.format(i)

        if (self.udp_value.get() == 1):
            resposta_text += 'UDP:\n'
            for i in udp_list:
                resposta_text += '{0}/UDP open\n'.format(i)

        self.resposta.delete(1.0,tk.END)
        self.resposta.insert('insert', resposta_text)

    # def scaner_network(self, event):
    #     print("Entrou aqui no NETWORK")
    #     print(self.entrada_rede.get())
        

scanner = BoardScanner()
scanner.iniciar()