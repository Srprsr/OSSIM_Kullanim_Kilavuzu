# OSSIM Kullanım Kılavuzu
OSSIM(Open Source Security Information Manager), SIEM (Security information and event management) fonksiyonunu destekleyen **Alienvault** tarafından geliştirilen open source bir yazılımdır. Üst düzey güvenlik için gerekli olan SIEM özelliklerini desteklemektedir. OSSIM'in amacı üst düzey güvenlik için oluşturulması gereken ortamdaki boşlukları doldurmaktır.

Son zamanlardaki **IDS** gibi güvenlik açısından gelişen teknolojiyi düşünecek olursak, şaşırtıcı bir şekilde Network'un snapshot'ını elde etmek neredeyse hattı gözetlemek kadar kompleks bir hal almıştır.

![alt text](http://cybersecurity-excellence-awards.com/wp-content/uploads/2016/01/638669-500x318.jpg "OSSIM Logo")

* [OSSIM Nedir?](#ossim-nedir?)
* [Installation and Configuration](#ınstallation-and-configuration)
* [OSSIM Konfigürasyonu](#ossın-konfigurasyonu)
* [OSSIM Mimarisi](#ossım-mimarisi)
* [OSSIM Login ve Bileşenler](#ossım-login-ve-bileşenler)

#Correlation

Bağıntı'nın anlamı, tüm sistemdeki tüm bağlantıları tek bir yerden ve tek bir formattan incelemek ve de bu ayrıcalıkla beraber bağlantıları birbirleriyle karşılaştırmak, bilgileri işlemektir. Bu durumda da , Network'un güvenlik durumunu izlerken, bizlere saldırı tespit sistemini kolaylaştırıp oldukça fayda sağlamaktadır.

Bağıntının bir diğer fikri de şudur ki; birbiriyle alakalı ürünler arasında entegre bir sistem olmasıdır. OSSIM'in bu yapısı, bizlere daha iyi fonksiyonda içeren ürünler üretmemizde yadsınamayacak şekilde destek vermektedir.

#Risk Oluşumu

Her bir durumda, bir durumdan dolayı oluşmuş olan tehdide karşı önlem alınıp alınmamasını, güvenliğin öncelikle düşünülerek, bu durumun gerçekleştirip gerçekleştirilmeyeceğine karar verilmelidir.
Bu durum sistemin daha fazla kompleks hale geldiği yerdir. Ve biz tam burada kendi güvenlik politikamızı hayata geçirmeli, Ve bağıntıda da bahsettiğim üzere tüm real time olarak tüm riskli bağlantıları tek bir yapıdan kontrol etmeliyiz. 

#OSSIM Nedir?
OSSIM open source bir yazılım olup, güvenliğin kontrol edilmesini sağlayan bir yapıdır.

OSSIM birleşik bir yapı olup vazgeçilemez güvenlik becerileri vardır. Bilindiği üzere bir çok open source yazılım OSSIM üzerine inşaa edilmiştir. Bu yazilimların bazıları şunlardır:

> * Apache
> * IIS
> * Syslog
> * Ossec
> * Snare
> * Snort
> * OpenVAS
> * Nessus
> * Nagios
> * Ntop
> * Nmap

OSSIM'in amacı yapıyı merkezileştirmek, organize etmek ve tespit sistemini attırmak ve gözlemlenen(monitoring) güvenlik durumlarını bizlere göstermektir.

Sistemimiz aşağıdaki gözlemleme parçalarını içerecektir:
* yüksek seviyede gözlemleme için panel
* Risk ve aktivite için orta seviye gözlemleme
* düşük seviyedeki Network ekranı

Bu araçlar SIM post-processing içerisine kurulunca bazı özel yetenekler elde ediyorlar. Bu yetenekler de güvenilirliği, hassaslığı ve tespit sistemini güçlendirmektedir.
* Correlation
* Prioritization
* Risk assessment

Post-processing önişlemcilerin kullanılması gibi düşünülebilir, belirli sayıda detektör ve gözlemleme aracının dahil olduğu organizasyonumuzda aşağıdaki unsurlar bir çok güvenlik yöneticisi tarafından bilinmektedir:
* IDS (pattern detectors)
* Anomaly detectors
* Firewalls
* Various monitors

Son olarak da bize gereken tek şey, organize yapıda olan bir araçtır. Buna da OSSIM diyoruz.

#Installation and Configuration
Iso dosyasını AlinVault'un şu sitesinden indiriyoruz =>**(http://downloads.alienvault.com/c/download?version=current_ossim_iso)** ve VM içerisinde kuruyoruz. Burada size Vm içerisinde yüklemeyi göstereceğim.

2 tane arayüzü bulunmaktadır. Birisi server yönetimi ile ilgili olup, 2. si ise collecting logs ve monitoring(inceleme) ile ilgilidir.
VM nin sahip olduğu özellikler aşağıda belirtilmiştir.

Processor :   2 VCPU ,  RAM   : 2 GB , Hard disk Size: 8GB , Management IP :  192.168.1.150/24 and Asset network  : 192.168.0.0/24

OSSIM iso maji ile ön yüklemede karşımıza 2 tane yükleme seçeneği çıkartıyor.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/first.png "OSSIM Logo")

Vurgulanan olan seçenek hangi yükleme türünün VM üzerinde seçildiğini gösteriyor. Yükleme işlemini başlatmak için **Start** tuşuna basıyoruz. Sonradan dil, bölge ve klavye seçeneklerini düzenliyoruz.

##Network Konfigürasyonu

Bu adımda, OSSIM'in Network'ünü VM de konfigüre ediyoruz. Burada yönetmek için eth0'ı kullanıyoruz. eth1'e bağlı olan diğer tüm networkler için, eth0 Network konfigürasyonu aşağıda gösterilmiştir.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/network-configuration.png "OSSIM Logo")
![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/combine.png "OSSIM Logo")
##Root Kullanıcısı Seçenekleri

Network seçeneklerinden sonra windows promt, OSSIM servere bağlantı için **root** ile bağlantılı olan kullanıcı şifresini istemektedir.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/rootuser.png "OSSIM Logo")
##Time Zone Seçenekleri

Time zone bilgisi giriş sistemi açısından oldukça öncem sarfetmektedir.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/timezone.png "OSSIM Logo")

Time zone seçeneğinden sonra, yükleme wizard'ı otomatik olarak paraçaları yüklemeye başlayacaktır. Bu adım 15-20 dakika arası sürmektedir.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/basesystem.png "OSSIM Logo")

Yüklemenin son adımı aşağıda gösterilmiştir.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/finsih.png "OSSIM Logo")

Yükleme bittikten sora aşağıda görülen windows promt ekramı açılacaktır. Bu ekran OSSIM'in yüklenmesinin başarı olduğunu söylemektedir. Ve OSSIM'e web arayüzünden üzerinden erişmek için gereken URL şudur:

```

https://192.168.1.150/

```


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/completion.png "OSSIM Logo")

Daha önce belirlediğimiz root adına olan şifre ile OSSIM server'e giriş yapıyoruz.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/login.png "OSSIM Logo")

Güncel olan Mozilla Firefox tarayıcısı bu linki açmamaktadır. Bu yüzden Chrome kullanmamızda fayda var. Chrome ile gerekli URL'yi girince karşımıza Aşağıdaki uyarı gelmektedir. Bu uyarının anlamı OSSIM kendi self signed sertifikasını kullandığı için Chrome, doğrudan buna güvenememektedir. Proceed seçeniğine basıp ilerlememiz gerekiyor.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/exception.png "OSSIM Logo")

Yukarıdaki durumu atlattıktan sonra, Karşımıa şu şekilde bir ekrançıkacaktır. Burda OSSIM server'i yöneticisi için gerekli bilgileri istemektedir. Bunları doldurmamız gerekiyor.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/information.png "OSSIM Logo")

Bir sonraki adımda karşımıza login ekranı geliyor ve bu ekranda account ve şifre giriyoruz. Ben burda Username olarak **admin** şifre olarak da **test@123** değerlerini girdim.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/loginscreen.png "OSSIM Logo")

OSSIM'im web arayüzüne başarılı bir şekilde giriş yaptıktan sonra daha fazla seçeneğin anlatıldığı bir wizard ekranı geliyor.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/wizardnew.png "OSSIM Logo")

Bu wizard bize 3 tane seçenekten bahsediyor. Bunlar:

* Monitor Network (Hangi Network'ün inceleneceği için gerekli olan konfigürasyon)
* Assets Discovery (Belli bir organizasyonun içinde bulunan tüm Network cihazlarını bulmak)
* Logları ve incelenen networkleri derleme.

Yukarıdaki ekran görüntüsünde yer alan  **start** butonuna tıklamamız gerekiyor.

Eğer birinci seçeneğe tıklarsak, karşımıza farklı bir pencere açılıyor. Burada log derleyicisi ve izleme arayüzü için eth1 konfigürasyonunu sağlıyoruz.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/network-configuration2.png "OSSIM Logo")

2. adımda ise , Organizasyon içindeki varlıklar için nasıl bir arama yapılmasını istedğimizi soruyor. OSSIM **manuel** ve **automatic** olarak 2 tane seçeneği önümüze sunuyor.

OSSIM serverlerindeki varlık tipleri şu şekildedir.

* Windows
* Linux
* Network device ( Network cihazları. Router gibi..)

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/asset.png "OSSIM Logo")

Network seçeneklerinden ve varlık keşfetmelerinden sonra bir sonraki adım, HIDS'in Windows ve Linux araçlarına dosya bütünlüğü ve Network incelemek için için dağıtımını görüyoruz. HIDS'in dağıtımı için araçlardaki kullanıcı adı ve şifreri giriyoruz.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/hids.png "OSSIM Logo")

İstenilen host'u host listesinden seçiyoruz ve HIDS dağıtımı için  **Deploy** butonuna tıklıyoruz. Başlaması için de **Continue** butonuna tıklıyoruz. Seçilen host için HIDS kurulumu başlıyor. Bu işlem bir kaç dakika sürmektedir.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/prompot.png "OSSIM Logo")
![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/deployming.png "OSSIM Logo")


**ÖNEMLİ: Bu bölümde OSSIM'in yeni arayüzü ile ilgili bilgiler vereceğim. Bu bölümün parçalarının detayları, kullanımı ve asıl detaylar dökümanın devamında yer alacaktır.**

##Giriş Yönetimi
Aşağıdaki görüntü, farklı loglar için keşfedilmilmiş varlıklar üzerinden konfigürasyonunu içeriyor. 

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/log-management.png "OSSIM Logo")

Ve son adımımız olarak Konfigürasyon seçeneklerimizi bitirmek için **finish** butonuna tıklıyoruz.

Burada OSSIM'in ana kontrol paneli karşımıza çıkacaktır. bu da, aşağıda görüldüğü şekildedir:

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/dashboard.png "OSSIM Logo")

##Web Arayüzü

OSSIM'in web arayüzü aşağıdaki parçalardan oluşmaktadır.

* Dashboards
* Analysis
* Environments
* Reports
* Configuration
 
##Dashboard

Bu bölümde OSSIM server'in tüm parçalarının incelenebildği bir paneldir. Bu panelin ana parçaları aşağıdaki gösterilmiştir.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/dashboard-submenu.png "OSSIM Logo")

#Analiz

Analiz kısmı OSSIM'in en önemli parçalarından biridir. OSSIM serveri hostları loglara göre analiz etmektedirler. Bu menüde Alarmlar, SIEM, ticket ve raw log gibi alt parçalara ayrılmaktadır.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/analysis-submenu.png "OSSIM Logo")
##Environment

OSSIM Server'in bu menüsünde de, seçenekler organizasyon içinde olan varlıklarla ilişkilidir. Aşağıda alt menüleri de görebilirsiniz.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/environment.png "OSSIM Logo")

##Raporlar

Raporlama herbir logging server için vazgeçilemez bir parçadır.Ayrıca, OSSIM server de kendisi raporları kendisi üretebilir. Bu durum yeni bir host'u sorgulamak için oldukça kullanışlı bir yoldur.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/reports-submenu.png "OSSIM Logo")

##Konfigürasyon

Konfigürasyon menüsün kullanıcının; yönetim arayüzünün ip adresi, hangi hostların inceleneceği gibi OSSIM serverindeki değişiklikleri yapabileceği bir bölümdür. Alt menüler aşağıdaki ekran görüntüsünde gösterilmiştir.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/configuration-submenu.png "OSSIM Logo")


#OSSIM Konfigürasyonu

İlk olarak **Policy => Networks** ekranına gidip  yeni bir **Network Policy** yaratıyoruz. Bu Network'ün kendine özel asset, compromise threshold ve saldırı threshold gibi değerleri var. Ek olarak da Network'ün içinde bulunan host'un Nessus ile taranmasını istiyosarsak bunu yapabiliyoruz. Herhangi bir asset değerini de herhangi bir host için spesifik hale getirebiliyoruz.

Network'ü taramak için **Tools => Netscan** bölümüne gidiyoruz. Bu ekran bize **nmap scan** taramasını çalıştırıp, bu taramanın hangi range aralığında olacağını önceki adımda girdiğimiz değerlere göre taramayı gerçekleştirmektedir. Aynı Network işlemlerindei gibi hangi hostların database eklenip eklenmeyeceğini seçebiliyoruz. Bunları modify etmek için de **Policy => Hosts** ekranına gitmemiz yeterli olacaktır.

Her bir host için OCS parçalarını çalıştırdığımızda. OCS, otomatik olarak host'tun sahip olduğu bilgileri bize getiriyor. OSSIM, OCS ile ilgili bütün bileşenlerini **Tools =>Downloads** kısmından görebiliyoruz. Bu tool OSSIM installer tarafından değiştirilmiştir. Yapılması gereken tek şey setup scripti çalıştırılmaktır. Bu parametreler de OCS'den OSSIM installer'a rapor olarak sunulmaktadır.

##Ayarlanabilir Eklenti
Bu bölümde güvenilirlik ve öncelik değerleri bir duruma tahsis edilir. Küçük bir plugin ile basit bir pyhton scrpti ile bu halledilebilir. Bu pyhton scripti syslog'a bir mesaj göndermektedir. Bu mesajda agent ve server doğrulanır.

##Server Konfigürasyonu
OSSIM Serverde, OSSIM database'i alakalı olan plugin ile  bilgileri güncellenmesi gerekmektedir. Aşağıdaki komutları kopyalayabiliriz. Bu komut satırı sql adında bir dosya yaratıcaktır. Eğer, dosyayı manuel bir şekilde yaratmak istiyorsanız blackslashlerden önce olan **’$’** sembollerini silmeyi unutmayın.


```

cat > ./foobar.sql << __END__
-- foobar
-- plugin_id: 20000
--
-- \$Id:\$
--
DELETE FROM plugin WHERE id = "20000";
DELETE FROM plugin_sid where plugin_id = "20000";
INSERT INTO plugin (id, type, name, description) VALUES (20000, 1, 'foobar',
'Foobar demo detector');
INSERT INTO plugin_sid (plugin_id, sid, category_id, class_id, reliability,
priority, name) VALUES (20000, 1, NULL, NULL, 6, 4, 'foobar: new foo found on
(DST_IP)');
INSERT INTO plugin_sid (plugin_id, sid, category_id, class_id, reliability,
priority, name) VALUES (20000, 2, NULL, NULL, 6, 1, 'foobar: foo the same on
(DST_IP)');
INSERT INTO plugin_sid (plugin_id, sid, category_id, class_id, reliability,
priority, name) VALUES (20000, 3, NULL, NULL, 10, 2, 'foobar: foo changed on
(DST_IP)');
INSERT INTO plugin_sid (plugin_id, sid, category_id, class_id, reliability,
priority, name) VALUES (20000, 4, NULL, NULL, 8, 3, 'foobar: foo deleted on
(DST_IP)');
INSERT INTO plugin_sid (plugin_id, sid, category_id, class_id, reliability,
priority, name) VALUES (20000, 5, NULL, NULL, 10, 5, 'foobar: alien foo on
(DST_IP)');
__END__

```
Yeni bir eklentinin OSSIM servere eklemek için aşağıdaki komut kullanılmalıdır.

```

cat foobar.sql | mysql -u root -p ossim

```
Burada OSSIM server yeni değerlerin farkında olması için tekrardan başlatılmalıdır.

```

/etc/init.d/ossim-server restart

```

Yeni bir eklenti varolduğunda, OSSIM web arayüzü bunu şu panelde doğrulayacaktır: **Configuration-> Plugins**

![alt text](http://i.hizliresim.com/0D60m9.jpg "OSSIM Logo")

Her bir plugin_sid'ye ait güvenilirlik ve öncelikle ilgili olan değerleri değerlerini değiştirdiğimizde, bu değerleri kullanması için OSSIM serveri tekrardan başlatmamız gerekmektedir.


##Agent Konfigürasyonu
Aşağıdaki adımların detayları yeni bir eklenti için agent'ı konfigüre etme yollarıdır. Bu yeni eklenti syslog çıktılarını inceleyecektir. Eklenti için yapılandırılan dosya plugin ID ile varolması gerekmekte ve syslog'daki bilgiyle birbirleriyle eşleşmelidirler. Bu durumda, sadece bir sid ile eşleşmelidir. Fakat, üstte gördügünüz sql komutlarında 5 farklı durum ve 5 farklı sub id vardır.


**Contents of /etc/ossim/agent/plugins/foobar.cfg** Bu satırı shell'e kopyalayabilir. Eğer dosyayı manuel bir şekilde oluşturuyorsak, **‘$’** 'den önce olan bütün bacskslashleri silmemiz gerekiyor. 

```

cat > /etc/ossim/agent/plugins/foobar.cfg << __END__
;; foobar
;; plugin_id: 20000
;; type: detector
;; description: foobar demo plugin
;;
;; URL:
;;
;; \$Id:\$
[DEFAULT]
plugin_id=20000
[config]
type=detector
enable=yes
source=log
location=/var/log/user.log
# create log file if it does not exists,
# otherwise stop processing this plugin
create_file=false
process=
start=no
stop=no
startup=
shutdown=
## rules
##
## New foo found in bar
##
[foobar - New foo found]
# Sep 7 12:40:55 eldedo FOOBAR[2054]: new foo found
event_type=event
regexp="(\S+\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<dst_ip>[^\s]*).*?FOOBAR.*?new foo
found"
plugin_sid=1
dst_ip={resolv(\$dst_ip)}
src_ip=0.0.0.0
date={normalize_date(\$1)}
[foobar - foo the same]
# Sep 7 12:40:55 eldedo FOOBAR[2054]: foo the same
event_type=event
regexp="(\S+\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<dst_ip>[^\s]*).*?FOOBAR.*?foo the same"
plugin_sid=2
dst_ip={resolv(\$dst_ip)}
src_ip=0.0.0.0
date={normalize_date(\$1)}
[foobar - New changed]
# Sep 7 12:40:55 eldedo FOOBAR[2054]: foo changed
event_type=event
regexp="(\S+\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<dst_ip>[^\s]*).*?FOOBAR.*?foo changed"
plugin_sid=3
dst_ip={resolv(\$dst_ip)}
src_ip=0.0.0.0
date={normalize_date(\$1)}
[foobar - New deleted]
# Sep 7 12:40:55 eldedo FOOBAR[2054]: foo deleted
event_type=event
regexp="(\S+\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<dst_ip>[^\s]*).*?FOOBAR.*?foo deleted"
plugin_sid=4
dst_ip={resolv(\$dst_ip)}
src_ip=0.0.0.0
date={normalize_date(\$1)}
[foobar - alien foo]
# Sep 7 12:40:55 eldedo FOOBAR[2054]: alien foo
event_type=event
regexp="(\S+\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<dst_ip>[^\s]*).*?FOOBAR.*?alien foo"
plugin_sid=5
dst_ip={resolv(\$dst_ip)}
src_ip=0.0.0.0
date={normalize_date(\$1)}
__END__


```
Bu durumda agent'a yeni bir eklenti olduğunu bildiriyoruz. ** Edit the file /etc/ossim/agent/config.cfg and add**. Aaşağıdaki satırı eklenti kısmında calıstırıyoruz.

```

foobar=/etc/ossim/agent/plugins/foobar.cfg

```
Şimdi agent'ı tekrar başlaıyoruz. Bu sayede yeni eklentinin farkında oluyor.
```

/etc/init.d/ossim-agent restart

```

##Doğrulama
Bu basit bir Syslog mesajı gönderen phyton script'i dir. Aşağıdaki kod phyton yüklü host'ta script olarak run edilebilir. 


```

#! /usr/bin/python
import syslog
import sys
syslog.openlog("FOOBAR", syslog.LOG_PID , syslog.LOG_USER )
for arg in sys.argv:
 if arg == "1":
 syslog.syslog(syslog.LOG_WARNING, "new foo found")
 elif arg == "2":
 syslog.syslog(syslog.LOG_WARNING, "foo the same")
 elif arg == "3":
 syslog.syslog(syslog.LOG_WARNING, "foo changed")
 elif arg == "4":
 syslog.syslog(syslog.LOG_WARNING, "foo deleted")
 elif arg == "5":
 syslog.syslog(syslog.LOG_WARNING, "alien foo")
syslog.closelog()

```
Bu programı etkinliğin gerçekleşmesini istediğimiz server üzerinde çalıştırıyoruz. Alttaki kodla birinci tip syslog mesajı yolluyoruz.

```

testfoobar.py 1

```
Bu ikinci mesajla da 5. tip syslog mesaj ilk olarak gönderiliyor, sonra 4. tip ve son olarak da 2. tip syslog mesajları sırasıyla gönderiliyor.

```

testfoobar.py 5 4 2

```
Etkinlikleri ve uyarıları kontrol ediyoruz. Önceden gösterilmiş etkinlikler sekmesinde bir etkinlik veya alarm görülmelidir.


#Basit bir OSSIM Direktifi
OSSIM kendi içindeki kurallarını serverde **/etc/ossim/server/directives.xml** isimli dosyada tutuyor. Bu kurallar direktiflere ayrılmış şekilde bulunuyorlar. Aşağıda gördüğünüz örnek ssh brute force direktifidir. Bu direktif gerekli bilgiyi **ssh auth log.plugin**'inden almaktadır. Aslında bu durumda saldırgan, tek bir host üzerinde host'u değiştirip saldırı girişiminde bulunup farkedilmekten kurtulabilir. Fakat, bu direktif bu saldırı girişimlerini yakalayacaktır.

```

<directive id="20" name="Possible SSH brute force login attempt against DST_IP"
priority="5">
  <rule type="detector" name="SSH Authentication failure" reliability="3"
    occurrence="1" from="ANY" to="ANY" port_from="ANY" port_to="ANY"
    time_out="10" plugin_id="4003" plugin_sid="1,2,3,4,5,6">
      <rules>
        <rule type="detector" name="SSH Authentication failure (3 times)"
          reliability="+1" occurrence="3" from="1:SRC_IP" to="ANY" 
          port_from="ANY" time_out="15" port_to="ANY" 
          plugin_id="4003" plugin_sid="1,2,3,4,5,6" sticky="true">
          <rules>
            <rule type="detector" name="SSH Authentication failure (5 times)"
              reliability="+2" occurrence="5" from="1:SRC_IP" to="ANY" 
              port_from="ANY" time_out="20" port_to="ANY" 
              plugin_id="4003" plugin_sid="1,2,3,4,5,6" sticky="true">
              <rules>
                <rule type="detector" name="SSH Authentication failure (10 times)"
                  reliability="+2" occurrence="10" from="1:SRC_IP" to="ANY" 
                  port_from="ANY" time_out="30" port_to="ANY" 
                  plugin_id="4003" plugin_sid="1,2,3,4,5,6" sticky="true">
                </rule>
              </rules>
            </rule>
          </rules>
        </rule>
      </rules>
    </rule>
</directive>


```


#OSSIM Mimarisi
![alt text](http://i.hizliresim.com/7vnaRl.jpg "OSSIM Logo")


![alt text](http://i.hizliresim.com/PMW1X8.jpg "OSSIM Logo")


![alt text](http://i.hizliresim.com/go0rmN.jpg "OSSIM Logo")



#OSSIM Login ve Bileşenler
OSSIM konsolu web üzerine kurulmuş olup, standart bir web tarayıcısı üzerinden 80 portundan (HTTP) veya güvenli olan 443 portundan (HTTPS)'den bağlanılabilir.

* Kullandığımız browser'ı açıyoruz.
* Addres yerine **http://ipaddressorofossimserver** yazıyoruz.
* OSSIM ID kullanıcı adımızı yazıyoruz.
* OsSIM şifresini giriyoruz. 


Default şifremizi değiştirmeyi unutmuyoruz ve buna özen gösteriyoruz.

Bir kere giriş yaptıktan sonra, Karşımıza **Metrics** ekranı gelmektedir. Metrics ekranın da ise izlemek istediğimiz Network'leri gözden geçiriyoruz. 

##Metrics Ekranı
![alt text](http://i.hizliresim.com/7vnB9N.jpg "OSSIM Logo")

Göründüğü gibi ekran farklı bölümlere ayrılmıştır. Bunlar **Global Metrics**, **Riskmeter**, **Service Level**, ve  policy'nin her bir parçası için **Current Metrics**.

#Policy Menüsü
OSSIM Policy menüsü yönetciye, policy inşaa etmek için gerekli olan objeleri yaratmaya ve bunları değiştirmeye izin verir.


##Yeni bir Sensör Yaratma
Aşağıda takip edilen adımlarla, yönetici bir OSSIM sensör ekleyebilir veya bunu değiştirebilir.
* **policy**'e tıklıyoruz.
* **sensors**Ee tıklıyoruz.

Karşımıza şu ekran çıkıyor. Burda farkettiğiniz üzere bu sensör önceden eklenmiştir.


![alt text](http://i.hizliresim.com/PMW78O.jpg "OSSIM Logo")

* **Insert new sensor**'e tıklıyoruz.
* 
Karşımıza şu ekran çıkacaktır. 

![alt text](http://i.hizliresim.com/go0PdO.jpg "OSSIM Logo")


* Add the Hostname - Host'unuzun ismi
* Add the IP Address - Host'un IP numarası.
* Add the Priority - Host'un ne kadar önemli olduğu ve önceliği. 5 en fazla öneme tekabül etmektedir.
* Add the Port - Serverin hangi port'una bağlı olacağına
* Add the description - Açıklama.

Objeyi oluşturmak için **OK**'a tıklıyoruz. Sensor yaratıldığında Sensorler ekranında eklemiş olduğumuz bilgileri görebiliyoruz.

![alt text](http://i.hizliresim.com/9L1YMN.jpg "OSSIM Logo")

Eğer eklenmiş yeni sensör aktif değilse, Aktif butonuna basarak bağlantıyı tekrar kontrol ediyoruz.

##İmza Gruplarını Tanımlama
İmzalar bölümü direkt olarak Snort ve sensörden okunan diğer imzala tipleriyle alakalıdırlar. Buradaki birbirinden bağımsız uyarılar 
ACID başlığı altında incelenebilirler. Bu bölümde yönetici, saldırılarla ilgili olan imzaları optimise edebilir. Bu bölüm Diğer sensörler için diğer imzaların açıklamalarını da taşıdığı için oldukça kullanışlı bir bölümdür. Örneğin, sadece Snort Virüs rules içeren Virüs tiplerinin imza listesi tutulabilir. 

Yeni bir imza grubu oluşturmak için:
* **Policy**'e tıklıyoruz.
* **Signatures**'a tıklıyoruz.
* **Insert new signature group**'a tıklıyoruz.

![alt text](http://i.hizliresim.com/qBkA6d.jpg "OSSIM Logo")


Karşımıza şu ekran çıkıyor.

![alt text](http://i.hizliresim.com/MJG1N1.jpg "OSSIM Logo")


Burada bir imza grubuna isim verebiliyoruz. Açıklamak istediğimiz imzaları seçiyoruz.
* Anlamlı olan kutulara tıklıyoruz.
* Kullanışlı bir açıklama ekliyoruz.
* **OK** butonuna basıyoruz.

Yeni imza eklenmiş oldu. İleride policy yaratman için kullanılmaya hazırdır.

##Bir Network Yaratmak
Genellikle Network gruplarının organizasyonu elimizde bulundururuz. Bunun için **The Policy >
Networks** Butonuna basıyoruz.
Karşımıza şu ekran çıkıyor.

![alt text](http://i.hizliresim.com/QM3PDy.jpg "OSSIM Logo")


Yeni bir Network eklemek için 
* **Insert new network**'e basıyoruz. 

![alt text](http://i.hizliresim.com/X41bV3.jpg "OSSIM Logo")


Aşağıdaki bileşenleri sırayla ekliyoruz.
* Name - Yeni Network veya Network grubunun ismi 
* Ips - Networklerin IP adresleri 
* Priority - Eklenilen Network'ün ne kadar önemli olduğunu belirtiyoruz. 5, en yüksek dereceye tekabül ediyor.
* Threshold - Alarmın verilmesiyse ilgili Thresholds değeri.
* Sensors - Hangi sensörün bu Network'ü izleyeceği.
* Scan options - Zayıflıkların taranıp taranmayacağına karar verildiği yer.
* Description - Network grubunun açıklaması.

 **OK** tuşuna basıyoruz ve  to Network grubu ekleniyor.
 **NOT:** Her bir Network grubunun periyodik olarak taranmasını istemiyorsak, Nessus Scan seçeneğini **DISABLED** yapmalıyız.

## İlgili Portların Eklenmesi
Bazı zamanlarda, OSSIM'in izlemesi gereken portların optimise edilmesi veya değiştirilmesi gerekmektedir. Bunu yapmak için de **Policy >Ports** Menüsüne giriyoruz.
Yeni bir port grubu oluşturmak için aşağıdaki adımlara harfi harfine uymamız gerekiyor.

* **Policy**'ye tıklıyoruz
* **Ports**'a tıklıyoruz.
* **Insert new Port Group**'a tıklıyoruz
* Bu port grubu için bir isim ekliyoruz
* İzlemek istediğimiz portları seçiyoruz
* Açıklama ekliyoruz
* Son olarak **OK** butonuna basıyoruz.

Yeni port grubu aşağıda görüldüğü gibi eklenmiş bulunuyor.

![alt text](http://i.hizliresim.com/bbXvqZ.jpg "OSSIM Logo")


## Priority & Reliability Değerlerini Değiştirme

OSSIM'de öncelik ve güvenilirliği Network'de alınan imzalar doğrultusunda değiştirilebilme imkanı vardır. Bu durum gerçektende yönetici için çok yararlı bir durumdur. Çünkü, yönetici bizi imzanın zayıflığı konusunda bizi uyarabilme şansına sahip olur.

Güvenilirliği ve önceliği değiştirmek için:
* **Policy**'e tıklıyoruz
* **Priority & Reliability**'e tıklıyoruz

Karşımıza çıkan ekran şu olacaktır.

![alt text](http://i.hizliresim.com/dbdLQD.jpg "OSSIM Logo")



Back Orifice'nin öncelik ve güvenilirliğini değiştirmek için,  **Id** alanına tıklıyoruz.

Aşağıda gördüğümüz ekran görütüsünde gördüğümüz üzere, Back orifice en yüksek önceliğe sahip. Güvenilirlik derecesi de 3'e set edilmiştir bunu değiştirmek içinde farklı bir değer girip **Modify** butonuna basılmalıdır.

![alt text](http://i.hizliresim.com/EJd2bv.jpg "OSSIM Logo")


Yukarıdaki görev OSSIM'i kendi network'ümüze göre optimize ettiğimizde, OSSIM tarafından üstlenilmiş bir görev olacaktır.


##Creating a Host
Önceki adımları tamamlamak için son işlemimiz diyebiliriz. Yeni bir host oluşturmanın iki farklı yolu vardır. Ya manuel bir şekilde ya da bilinen bir hostun networkde scan edip o host hakkında bilgi alınması şeklindedir.

**Policy > Hosts** menü, Host operating system şeklinde P0F kullanarak detect edilmesi aşağıdaki şekildedir. 

![alt text](http://i.hizliresim.com/jnOAL9.jpg "OSSIM Logo")


Yeni bir host eklemek için

* **Insert new host**'a tıklıyoruz.
* Aşağıda görülen tüm yerlere anlamlı bilgileri giriyoruz.

![alt text](http://i.hizliresim.com/2Z3PyL.jpg "OSSIM Logo")


**Önemli : Burada Nessus scan'i akif etmeliyiz. Bu durumda large bir network kullanıyorsak bütün zayıf noktaları görmemize gerek kalmaz. Asıl yapılması gereken, belirli olarak seçeceğimiz bir hostta zayıflıklar var mı yok mu görmek daha faydalı olacaktır.**

Gerekli bilgiler doldurulduğunda **OK** butonuna basılmalıdır. Bu yeni host artık host listesinde yer alacaktır. Eğer gilgiler yanlış yazılmış ise **Modify** Butonunu kullanarak, bu bilgiler güncellenebilir.

### Updating and the host information.
Yeni bir host'un bilgilerini update etmek için, **Host Field** kısmından bilgileri değiştirilmek istenen host ismine tıklanır. Ve karşımıza şu şekilde bir ekran çıkacaktır.

![alt text](http://i.hizliresim.com/B2QGEV.jpg "OSSIM Logo")


Host inventory'sini update etmek için **update** butonuna basılır. Yeni hostlara karşı Nmap scan başlatılır. Bu durum açık portları elde etmemize yararken, servis sistemde aşağıdaki gibi çalışmaktadır.

![alt text](http://i.hizliresim.com/ZdBnLg.jpg "OSSIM Logo")


Spesifik bir host için **Metrics**'i incelemek için, **Metrics** Butonuna basılmalıdır. Karşımıza çıkacak olan Metrics grafiği atakları gösterir. Bu grafik gün bazında, ay bazında olacağı gibi yıl bazında da olabilir.

![alt text](http://i.hizliresim.com/o7WyAQ.jpg "OSSIM Logo")


### Alarms and Alerts
Host Report menüsünde 3 tane alt bölüm bulunmaktadır. Bunlar; **Vulnerabilities**, **Alarms**, ve **Alerts** dir. Peki alarm ve Alert arasındaki fark nedir?

Belirli olan belli başlı kriterler sağlandığında alarm ortaya çıkar. Örneğin, şu durumlar gerçeleştiğinde alarm durumu oluşur.

* Snort tarafından bir alert oluşturulduğunda.
* Alarmla ilgili bir attack detect edilirse.
* Spesifik thresholds değeri geçilirse.
* Sistemin güvenlik öncliği yeteri kadar yüksekse.

Bütün bu durumlar alarm oluşturmak için gereklidir.

Ek olarak, Snort veya Spade spesifik bir saldırı imzası yakalarsa alarm durumu oluşur.  Bu durum, **ACID** – **A** **C**onsole for **I**ntrusion **D**etection kısmında gösterilir. ACID tool'u bu dökümanın sonraki bölümlerde anlatacağım.

Alarm seçenekleri **Source** veya **Destination**, **Source** ve **Destination** dir.
Alerts seçenekleri ise **Main**, **Source**, ve **Destination** dir.

Yukarıdaki Alarm seçeneklerden herhangi birisine basıldığında o alarmın hangi host ile alakalı olduğunu gösterecektir. 


###Alerts
Alert'ler ACID sayrsinde elde edilir. ACID konsoluna ulaşmak için User ID ve password gereklidir.

* **Main**'e Tıklıyoruz.

Bir login ekranı ile karşılaşacağız. Default User ID ve Password aşağıda yazılmıştır.

USER ID: acid
PASS: acid_password

Yükleme kısmında ID ve Password dilenildiğince değiştirilebilmektedir.

Eğer başarılı bir şekilde login olunursa, yönetici şu ekranla karşılaşılacaktır.

![alt text](http://i.hizliresim.com/l1G4kB.jpg "OSSIM Logo")


### the ACID console Kullanımı.
ACID çok önemli bir araç olup ihlalleri tespit edip bununla ilgili bilgileri kullanıcıya verir.
OSSIM'le ilgili oldukca da bağlantılı olup daha fazla bilgiyi **http://acidlab.sourceforge.net** sayfasından elde edebilirsiniz. 

Aşağıda ACID'in basit bir örneklendirmesini görebilirsini görebilirsiniz.

Saldırıların oluşumuna bakmak için **Occurances as Src.** kısmına tıklanmalı ve detect edilen imzalar ve saldırılar görülebilir.

![alt text](http://i.hizliresim.com/VYnBly.jpg "OSSIM Logo")


Herhangi bir imza ile ilgili daha fazla bilgi almak için **[snort]** üzreine tıklanmalı ve bu bizi Snort rules tanımlarının olduğu sayfaya yönlendirecektir. Bu sayfada imza ile ilgili önemli bilgiler yer almaktadır.

### Vulnerabilities
OSSIM, şirketlere ve bireysel kullanıcılara kendi serverlerindeki önde gelen zayıf noktaları inceleme imkanı sağlar. Bunu sağlayan **Host Repot** menüsüdür. Bu bölüm zayıf noktaların raporlarını elde eder ve bu noktaları tarar. Bu incelemelerin sonucunu da görmek için önce **Vulnmeter** başlığı altındaki **Vulnerabilities** bölümüne bakmamız yeterli olacaktır.

Bu bölümde zayıflıkları olan hostların listesi gelecektir. ve ilgili host ve ilgili IP adress highlighted şekilde gözükecektir. Üzerinde çalışılmak istenen host ve IP adresin üzerine tıklanması gerekir.

![alt text](http://i.hizliresim.com/nr6yA5.jpg "OSSIM Logo")


Daha fazla bilgi edinmek için **(Security hole found)** seçeneğine tıklanmalı ve sekme aşağı indirilmelidir.

### Host Usage
Host usage ile ilgili bilgiler **NTOP** tarafından sağlanmaktadır. Daha fazla bilgiyi **http://www.ntop.org.** adresinden elde edebilirsiniz. Trafik akışındaki şüpheli durumlar içn OSSIM, NTOP'u kullanmaktadır.

![alt text](http://i.hizliresim.com/v42ygm.jpg "OSSIM Logo")


### Anomalies
Anomalies host'un normal davranışının değişmesidir. Bu bölümde **işletim sistemi** ve **MAC adresi** değişmelerini içermektedir. Anomalie'ler, yaratılmış olan RDD_Config'e göre değişiklik gösterirler. Bütün anomalie'leri görmek için **Control Panel > Anomalies**
bölümüne girilmelidir. Sonradan karşımıza şu ekran çıkacaktır.

![alt text](http://i.hizliresim.com/R3ZGkG.jpg "OSSIM Logo")


Değişiklikler farkedilebilir ya da görmezden gelinebilir.

## Creating a Policy
Policy yaratmak, OSSIM için en önemli durumlardan biridir. Çünkü, yaratılan policy ile hostların ve networklerin izlenme işlemleri yapılır. Buna göre de anlamlı ve istenilen bilgiler elde edilir.

* **Policy**'ye tıklıyoruz.

Aşağıdaki resimde, gösterilen network için bir kaç tane hali hazırda varolan policy olduğunu görüyoruz.

![alt text](http://i.hizliresim.com/pP32zN.jpg "OSSIM Logo")


Yeni bir policy eklemek için, **Insert new policy**'a tıklanır. Sonrasında karşımıza şu ekran çıkar.

![alt text](http://i.hizliresim.com/kvz0B7.jpg "OSSIM Logo")


* Source addresler seçilir.
* Destination addresler seçilir.
* Portlar seçilir
* Priority seçilir
* İmzalar seçilir
* Bu policy'de hangi sensörün çalışması istendiği bilirlenir
* Time range belirlenir.
* Policy için bir tanım verilir
* Kaydedilmesi için **Ok** tuşuna basılır. 

# Reports
Reports, OSSIM'in sağladığı hostlar ve tüm network güvenliği için bilgi edinilmesini sağlayan bir menüdür. Gelen report'lar isteğe göre değiştirilebilir ve hangi raporların görülüp görülmeyeceğini kullanıcı tarafından seçilebilir.

The Security Report bölümü aşağıdaki bilgileri sağlar. 

![alt text](http://i.hizliresim.com/NEBGAN.jpg "OSSIM Logo")


 **Top 10 Alerts**'a tıkladığımızda, karşımıza şu ekran çıkacaktır.

![alt text](http://i.hizliresim.com/aEQg3R.jpg "OSSIM Logo")

Bu ekranda, verilem alert'ler hakkında bilgi edinebildiğinden oldukça kullanışlı bir bölümdür. Ayrıca görünmesini istemediğimiz alert'ları bu menüdeyken silebiliriz.

# Monitors Menu
Bu bölümde Session, Network, Availability ve Riskmeter gibi alt başlıklar yer almaktadır.
Monitor menüsü  real-time network, uptime, ve risk session data gibi seçenekleri sağlar. Bu bölümdeki bilgilerin çoğunu NTOP ve OpenNMS sağlar.

* NTOP – http://www.ntop.org
* OPENNMS – http://www.opennms.org

##RiskMeter 

![alt text](http://i.hizliresim.com/YbLVka.jpg "OSSIM Logo")

Riskmeter risk altında olan veya saldırı gerçekleştirilen sistem hakkında bilgi edinilmesini sağlar. Bu riskmeter'in nasıl hesaplandığını öğrenmek için OSSIM websitesini ziyaret edebilirsiniz http://www.ossim.net. 

#Configuration Menu

Configuration menüsü, yöneticiye Ossimin seçeneklerini değiştirme imkanı sağlar. Sub menüler ise reload all policies, edit directives , view correlation, information, create or modify RDD_Config information, add a host to scan, and edit the global riskmeter configuratin gibi seçenekleri içermektedir.

##Sub Menus

###Main
Main menü' de bir çok ayrı ayrı parçalar bulunmaktadır.

![alt text](http://i.hizliresim.com/81vXZr.jpg "OSSIM Logo")


### Directives

Directives dediğimizde alarm'a neden olan olayların hepsi olarak düşünebiliriz. Bu durumlar herhangi bir altyapıya göre optimise edilebilir. Aşağıdaki ekran görüntünsünde, win-trin00 Trojan'ı için default directive görünmektedir.


![alt text](http://i.hizliresim.com/DJbG21.jpg "OSSIM Logo")


Directive'ler plugin ID'ler tarafından değiştirebilirler. Örneğin, Ossime tıklayıp karşımıza şu ekran çıktığında, bu ekranda yöneticiye öncelik ve güvenlik olan OSSIM durumlarını değiştirme imkanı veriyor.

![alt text](http://i.hizliresim.com/mLyR6y.jpg "OSSIM Logo")


### RRD Configuration
RDD biçimlendirme, alınmak istenen uyarılar için yönetecinin anlamlı değerler ve de thersholds değerlerini girmesini sağlar.
Aşağıdaki örnekte default RDD_Config ve default seçenekler mevcut. Fakat, farklı bir RDD configuration ekleyebiliriz. Bu da aşağıda şekildeki gibi olmaktadır.


####Yeni Bir RRD Configuration Ekleme. 

![alt text](http://i.hizliresim.com/EJd289.jpg "OSSIM Logo")

* **Configuration > RRD_Config**'a tıklıyoruz.
* **Insert new rrd_conf**' a tıklıyoruz.

Karşımıza çıkan ekranda, biçimlendirilmesine izin verilen bireysel network'ler veya host'lar görülüyor.

* Monitor'e bir IP addresi ekliyoruz.
* thresolds değerini aşağıdaki ipucu değerlerine göre değiştiriyoruz.

![alt text](http://i.hizliresim.com/ZdBnZZ.jpg "OSSIM Logo")


## Host Scan
Host scan seçeneği kullanıcıya scan edilecek olan host listesine, scan edilmesi istenen host'un eklenmesini sağlar. Bu çok tercih edilen bir yöntem değildir. Bunun yerine **Policy > Hosts > Insert new host** menüsünden bu seçeneği eklemek daha iyi bir fikirdir.


##Riskmeter configuration
Aşağıdaki screenshoot'dan görüleceği gibi, default configuration **Configuration > Riskmeter** bölümünden değiştirilebilir.

![alt text](http://i.hizliresim.com/o7Wyjk.jpg "OSSIM Logo")


# Tools
Tools menüsüne tıklandığında Scan host, view alarm backlog ve view rules gibi seçenekleri görürüz.


## Scan
Scan seçeneği tanımlanmış Network range'indeki tüm ip adreslerini tarar. Bu sayede, hangi host'un çalışıp çalışmadığı hakkında bilgi verir. Belli bir range'yi taramak için aşağıdaki range değeri girilmeli ve **OK** tuşuna basılmalıdır.

![alt text](http://i.hizliresim.com/l1G4db.jpg "OSSIM Logo")


## Backlog Viewer
Backlog viewer, öne çıkan anormallikler hakkında bilgi edinilmesini sağlar.


## Rule viewer
Rule viewer, yöneticiye kuralları ayrı ayrı gösteren bir paneldir.  **Tools > Rule
Viewer** butonuna tıkladıktan sonra, incelenmek istenen kural seçilir. Aşağıdaki durumda virüsle ilgili olan kural yer almaktadır.

![alt text](http://i.hizliresim.com/VYnB0r.jpg "OSSIM Logo")

