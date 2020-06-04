from tkinter import *
import threading
from tkinter import messagebox
import psutil


from PIL import ImageTk,Image
from scapy.all import Ether, ARP, srp, sniff, conf
from tkinter.ttk import *
# Create the root window 
# with specified size and title 
root = Tk()
root.configure(background="#0e0d30")
root.title("Minimalistic tool")   
#root.geometry("520x300")   



label1 = Label(root, text = "Detection of Promiscuous mode and ARP poisoning", background="#000d1a" ,foreground="lightgreen", font="Serif 14 bold").pack(pady=10)
background_image =ImageTk.PhotoImage(file='imagess.jfif') 
pic=Label(image=background_image).pack(fill="none",expand=True)






e = threading.Event()


addrs = psutil.net_if_addrs()
OPTIONS = [
   "----"
    ]
for interface in addrs:
    OPTIONS.append(interface)

def get_mac(ip):
    """
    Returns the MAC address of `ip`, if it is unable to find it
    for some reason, throws `IndexError`
    """
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=True)[0]
    return result[0][1].hwsrc
    
  
def process(packet):
    # if the packet is an ARP packet
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                print(real_mac)
                # get the MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                print(response_mac)
                # if they're different, definetely there is an attack
                if real_mac != response_mac:
                    
                    
                    g.insert(0,'YOU ARE BEING ATTACKED')
                    
                    e.set()
                    
            except IndexError:
                
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass



#This is used to call sniff fuction  
def sniffs(e):
    g.delete(0,'end')
    
    iface = variable.get()
    
    sniff(store=False, prn=process, iface=iface, timeout = 15,stop_filter=lambda p: e.is_set())
    
    if not e.is_set():
        
        g.insert(0,'YOU ARE SAFE')
    e.clear()



# this fuction is used to 
def promiscs(e1):
    try:
      y.delete(0, 'end')
      ip=e1.get()
      if ip == "":
        y.insert(0, 'ENTER IP ')
        return
      
      t=get_macs(ip)
      y.insert(0,'ON ')
    except:
      y.insert(0,'OFF')
      

# here we send a packet with dst as 01:00:00:00:00:00 such that no other device in the network except for a promiscuous mode enabled device recives it.
def get_macs(ip):
    promisc_test = Ether(dst='01:00:00:00:00:00')/ARP(pdst=ip)
    result = srp(promisc_test,timeout=3,verbose=True)[0]
    return result[0][1].hwsrc
    
    











    
# define a function for 2nd toplevel  
# window which is not associated with  
# any parent window 


def open_Toplevel2():  
    
    style = Style() 
  
# This will be adding style, and  
# naming that style variable as  
# W.Tbutton (TButton is used for ttk.Button). 
  
    style.configure('W.TButton', font =
                   ('calibri', 10, 'bold', 'underline')
                    ,foreground='red')  
    # Create widget 
    top2 = Toplevel(bg='#0e0d30')  
      
    # define title for window 
    top2.title("Promiscious Mode") 
      
    # specify size 
    top2.geometry("450x250") 
    # Create label 
    label = Label(top2, 
                  text = "Promiscious Mode", font='Serif 18 bold',background="#0e0d30",foreground="lightgreen").pack()
    
    #bgimage =ImageTk.PhotoImage(Image.open("back.jpg")) 
    #background2=Label(image=bgimage).pack()
    label = Label(top2, 
                  text = "IP Address :").place(relx=0.1,rely=0.2,relheight=0.1,relwidth=0.3)
    e1 = Entry(top2)
    e1.place(relx=0.5,rely=0.2,relheight=0.1,relwidth=0.3)
    l=e1.get()  
    # Create exit button. 
    exit = Button(top2,text = "Exit" , style = 'W.TButton',
                    command = top2.destroy,cursor="X_cursor") 
    exit.place(relx=0.1,rely=0.5,relheight=0.1,relwidth=0.3)
    start = Button(top2, text = "Start", command = lambda : threading.Thread(target=promiscs,args=[e1]).start(),cursor="spider"
                    )
    start.place(relx=0.5,rely=0.5,relheight=0.1,relwidth=0.3)
    result = Label(top2, 
                  text = "Result :").place(relx=0.1,rely=0.8,relheight=0.1,relwidth=0.3)
    global y
    y = Entry(top2,font='Serif 10 bold')
    y.place(relx=0.5,rely=0.8,relheight=0.1,relwidth=0.3)
    
    
    
    
      
    # Display untill closed manually. 
    top2.mainloop() 
       

global progress
progress = Progressbar(root, orient = HORIZONTAL, 
              length = 100, mode = 'determinate')

# define a function for 1st toplevel 
# which is associated with root window. 

def open_Toplevel1():   
      
    # Create widget 
    top1 = Toplevel(bg='#0e0d30') 
    style = Style() 
      
    # Define title for window 
    top1.title("ARP POISONING")
    style.configure('W.TButton', font =
                   ('calibri', 10, 'bold', 'underline')
                    ,foreground='red')  

    # specify size 
    top1.geometry("400x250") 
    
      
    # Create label 
    label = Label(top1, 
                  text = "ARP POISONING", font='Serif 18 bold',foreground="lightgreen",background="#0e0d30").pack(pady=10)
    label = Label(top1, 
                  text = "Specify interface :").place(relx=0.1,rely=0.22,relheight=0.1,relwidth=0.3)
    global variable
    variable = StringVar(top1)
    variable.set(OPTIONS[0]) # default value

    w = OptionMenu(top1, variable,*OPTIONS)
    w.place(relx=0.5,rely=0.22,relheight=0.1,relwidth=0.3)
    
    
    
      
    # Create Exit button 
    
    
    button1 = Button(top1, text = "Exit", style = 'W.TButton',
                     command = top1.destroy,cursor="X_cursor")
    button1.place(relx=0.1,rely=0.5,relheight=0.1,relwidth=0.3)
    button = Button(top1, text = "Start", command = lambda : threading.Thread(target=sniffs(e)).start(), cursor="spider"
                    )
    button.place(relx=0.5,rely=0.5,relheight=0.1,relwidth=0.3)
    label = Label(top1, 
                  text = "Result :").place(relx=0.1,rely=0.8,relheight=0.1,relwidth=0.3)
                  
    global g
    g = Entry(top1)
    g.place(relx=0.5,rely=0.8,relheight=0.12,relwidth=0.5)
    
   
      
    # create button to open toplevel2 

    # Display untill closed manually 
    top1.mainloop() 
  




# Create button to open toplevel1 
R1 = Button(root, text = "PROMISCUOUS MODE", command = open_Toplevel2,cursor="target"
                 )

R1.pack(padx=40,pady=10,ipadx=40)


R2 = Button(root, text = "ARP POISONING",command = open_Toplevel1,cursor="target")
R2.pack(padx=40,pady=10,ipadx=55)
#label1.grid() 
  
# position the button 
#R1.place(x = 20, y = 100) 
#R2.place(x =20, y = 200)

#R3.place(x=20, y = 90) 
ourMessage ='“Technology trust is a good thing, but control is a better one.”'
messageVar = Message(root, text = ourMessage) 
messageVar.config(bg='lightgreen') 
messageVar.pack()
#messageVar.place(x = 400, y = 200)
    
# Display untill closed manually 
root.mainloop() 

