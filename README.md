# OSSIM Kullanım Kılavuzu
OSSIM(Open Source Security Information Manager), SIEM (Security information and event management) fonksiyonunu destekleyen **Alienvault** tarafından geliştirilen open source bir yazılımdır. Üst düzey güvenlik için gerekli olan SIEM özelliklerini desteklemektedir. OSSIM'in amacı üst düzey güvenlik için oluşturulması gereken ortamdaki boşlukları doldurmaktır.

Son zamanlardaki **IDS** gibi güvenlik açısından gelişen teknolojiyi düşünecek olursak, şaşırtıcı bir şekilde Network'un snapshot'ını elde etmek neredeyse hattı gözetlemek kadar kompleks bir hal almıştır.

![alt text](http://cybersecurity-excellence-awards.com/wp-content/uploads/2016/01/638669-500x318.jpg "OSSIM Logo")

#Bağıntı

Bağıntı'nın anlamı, tüm sistemdeki tüm bağlantıları tek bir yerden ve tek bir formattan incelemek ve de bu ayrıcalıkla beraber bağlantıları birbirleriyle karşılaştırmak, bilgileri işlemektir. Bu durumda da , Network'un güvenlik durumunu izlerken, bizlere saldırı tespit sistemini kolaylaştırıp oldukça fayda sağlamaktadır.

Bağıntının bir diğer fikri de şudur ki; birbiriyle alakalı ürünler arasında entegre bir sistem olmasıdır. OSSIM'in bu yapısı, bizlere daha iyi fonksiyonda içeren ürünler üretmemizde yadsınamayacak şekilde destek vermektedir.

#Risk Oluşumu

Her bir durumda, bir durumdan dolayı oluşmuş olan tehdide karşı önlem alınıp alınmamasını, güvenliğin öncelikle düşünülerek, bu durumun gerçekleştirip gerçekleştirilmeyeceğine karar verilmelidir.
Bu durum sistemin daha fazla kompleks hale geldiği yerdir. Ve biz tam burada kendi güvenlik politikamızı hayata geçirmeli, Ve bağıntıda da bahsettiğim üzere tüm real time olarak tüm riskli bağlantıları tek bir yapıdan kontrol etmeliyiz. 

#WHAT IS OSSIM?
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

Its objective is to provide a framework for centralizing, organizing, and improving detection and
display for monitoring security events within the organization.
Our system will include the following monitoring tools:
* Control panel for high-level display
* Risk and activity monitors for mid-level monitoring
* Forensic console and network monitors at the low level

These tools utilize new capabilities developed in SIM post-processing, whose objective is to improve
detection reliability and sensitivity:
* Correlation
* Prioritization
* Risk assessment

Post-processing in turn makes use of the preprocessors, a number of detectors and monitors already
known to most of the administrators that will be included in our distribution:
* IDS (pattern detectors)
* Anomaly detectors
* Firewalls
* Various monitors

Finally, we need an administrative tool that configures and organizes the various modules, both
external and native, that comprise OSSIM. That tool is the framework, which allows us to inventory
assets, to define: the topology, a security policy, correlation rules, and to link up the various integrated
tools.

#Installation and Configuration
Download an iso from AlienVault **(http://downloads.alienvault.com/c/download?version=current_ossim_iso)** and install it in the VM . In this tutorial, we will install OSSIM on VM instead of physical server which has following specifications

It has two interfaces, one is for the management of server and 2nd is for collecting logs and monitoring of the network devices. The details of the VM are  given below.

Processor :   2 VCPU ,  RAM   : 2 GB , Hard disk Size: 8GB , Management IP :  192.168.1.150/24 and Asset network  : 192.168.0.0/24

When OSSIM VM boots with iso image, it shows following two option at installation wizard.



![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/first.png "OSSEC Logo")
Highlighted option in above figure is selected which will install OSSIM on this VM. Press enter to start the installation process. Select language, location and keyboard setting in next few steps.

##Network Configuration

In this step, configure the network of OSSIM VM. We are using eth0 for the management and rest of the network is connected to eth1. Network configuration for eth0 is shown below.



![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/network-configuration.png "OSSEC Logo")
![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/combine.png "OSSEC Logo")
##Root User Setting

After network setting, next windows prompt for the password of user root which can access the CLI of OSSIM server. Password of root user must be strong.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/rootuser.png "OSSEC Logo")
##Time Zone setting

Time zone information is important in logging system and shown below.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/timezone.png "OSSEC Logo")

After setting time zone, wizard automatically perform the partition step and start installing the base system. This step will take almost 15-20 minute.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/basesystem.png "OSSEC Logo")

Final stage of installation is shown in following figure.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/finsih.png "OSSEC Logo")

Following windows prompt after the complete installation of AlienVault OSSIM. We can access the  web interface using following URL:
```
<localfile>
https://192.168.1.150/
<localfile>
```


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/completion.png "OSSEC Logo")

Login with user root and password test in CLI of OSSIM server.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/login.png "OSSEC Logo")

Latest Mozilla firefox browser does not open the link, so use Chrome or IE browser for the access of web interface. Chrome and IE will prompt following windows which says that certificate are not trusted because OSSIM uses self signed certificate.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/exception.png "OSSEC Logo")

After acceptance of above exception, following information required for the administrator of OSSIM server. Fill the required details which are asked in the following figure.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/information.png "OSSEC Logo")

Following windows will appear after the completion of administration account. Username is admin and password is test@123.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/loginscreen.png "OSSEC Logo")

After successful log in into the web interface, following wizard appear for further setting of OSSIM server.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/wizardnew.png "OSSEC Logo")

It shows following three options

*Monitor Network (Configure  network which is being monitored by the OSSIM server)
*Assets Discovery (Automatic discovery of network devices in the organization )
*Collecting logs and monitoring of network nodes
Click on the **start** button of the above figure  for the configuration of OSSIM server.

After clicking on the 1st option, another windows will  prompt for the network configuration which is shown in the below figure. We  configured eth1 for the log collector and monitoring interface of the OSSIM server.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/network-configuration2.png "OSSEC Logo")

In the 2nd step, OSSIM will perform automatic discovery of  the network assets . select Asset discovery (2) option and following windows will prompt for the  configuration. It supports automatic and manual discovery of assets .

Type of Assets in the OSSIM server are

*Windows
*Linux
*Network device

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/asset.png "OSSEC Logo")

After network setting and asset discovery, next step is the deployment of HIDS on windows/linux devices to perform file integrity, monitoring, rootkit detection and  collection of  event logs. Enter username/password of the asset for the deployment of HIDS.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/hids.png "OSSEC Logo")

Select desired host from the list and click on Deploy button for the HIDS deployment. Again click on  Continue button to start deployment process which is shown in the  figure. This process will take a few minute for the HIDS deployment on selected host.


![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/prompot.png "OSSEC Logo")
![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/deployming.png "OSSEC Logo")

##Log Management
Following figure showing the configuration of discovered asset for the management of different logs.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/log-management.png "OSSEC Logo")

Final option of the configuration wizard  is to join OTX (Threat exchanged program of AlienVault). We are not going to sign up for this option. Finish the configuration step by clicking on finish button.

The main dashboard of the OSSIM server is shown below .

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/dashboard.png "OSSEC Logo")

##Web Interface

Web interface of OSSIM server consist of following options on the main GUI.

*Dashboards
*Analysis
*Environments
*Reports
*Configuration
 
##Dashboard

It show a comprehensive view of all components of OSSIM server like severity of threat, vulnerabilities in the networks host, deployment status , risk maps and OTX stats. Sub menu of dashboard is shown in the following figure

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/dashboard-submenu.png "OSSEC Logo")

##Analysis

Analysis is very important component of any SIEM device. OSSIM server analyzed the hosts based on their logs. This menu shows the alarms, SIEM (security events),tickets and raw logs. Analysis menu is further divided following sub menu.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/analysis-submenu.png "OSSEC Logo")
##Environment

In this menu of OSSIM server, setting are related to the assets of the organization. It shows the assets, group and network, vulnerabilities, netflow and detection settings. Sub menu for all these settings is shown in the figure.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/environment.png "OSSEC Logo")

##Reports

Reporting is an important component of any logging Server. OSSIM server also generates reports which are very useful for the detail investigation of any specific host.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/reports-submenu.png "OSSEC Logo")

##Configuration

In the configuration meHow to Install and Configure AlienVault SIEM (OSSIM)nu, user can change the setting of OSSIM server such as change the ip address of management interface, add more host for monitoring and logging and add/remove different sensors/plugins. Sub menu for all services is shown below.

![alt text](http://blog.linoxide.com/wp-content/uploads/2015/02/configuration-submenu.png "OSSEC Logo")

In this article,we explain the installation and configuration process of open source SIEM software which is backed by AlienVault. In our next article, our focus will be on the details of all components of OSSIM.



#Configuration of OSSIM

To begin to see the value OSSIM provides, policies need to be created. Dominique Karg of the OSSIM
development team has written a series of tutorials including one describing initial steps after
installation. http://www.ossim.com/home.php?id=download . The following is a summary of the steps
described in his tutorial. I will go through the steps briefly, but I highly recommend following his
tutorial directly.
First, create a network policy by going to to the screen **Policy => Networks** and specify a network.
This network is given an asset value, a compromise threshold and an attack threshold values. In
addition, you can specify whether you want hosts in this network to be scanned by Nessus and if Nagios
is enabled. See the Creating Assets and Calculating Risk section below for detailed information about
how to assign risk. Individual asset values can also be specified for hosts, which will override the value
given to the network. 
Scan the network you just specified by going to the screen **Tools => Netscan** . This will run an
nmap scan across the range of IP addresses that you specified in the previous step. It will list the hosts it
found along with the services for each host. You can choose which ones are inserted into the database.
The risk value given for the inserted hosts will be same as the network. It can be modified for each host
by going to the screen **Policy => Hosts**.
Perform an OCS inventory for each host. OCS automatically collects information about the host
operating system, configuration, and installed software. OSSIM integrates the OCS tools into its **Tools
=> Downloads** screen. The tool has been customized by the OSSIM installer, so all that needs to be
done is run the setup script. The configuration parameters are already set to report OCS details back to
the OSSIM installer

##A Customized Plugin
This is an area where priority and reliability is assigned to an event. OSSIM allows for the creation of
custom plugins that will capture events specific to a user's network. This will focus on the steps needed
to create an OSSIM plugin. This will be a simple plugin that you can trigger using a small python script

Illustration 4: Events Tab
OSSIM Brian E. Lavender
that sends a message to syslog. This process can be used to verify that the agent and server are
functioning and that the agent can send information to the server. It will also serve as a tutorial for
configuring and utilizing other plugins.

##Server Configuration
In the previous tables showing risk, an event came from a foobar plugin. The following demonstrates
how to create the a plugin for foobar. On the OSSIM server, the ossim database needs to be updated
with information regarding the plugin. You can copy and paste the following and it will create the file
with the sql. If you create the file manually, be sure to remove the backslashes before any ‘$’ symbol. 

```
<localfile>
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
</localfile>
```

Now the plugin can be inserted into the OSSIM server using the following command.
```
<localfile>
cat foobar.sql | mysql -u root -p ossim
</localfile>
```

The OSSIM server must be restarted so that it is aware of the new plugin information.

```
<localfile>
/etc/init.d/ossim-server restart
</localfile>
```

Once the plugin exists the OSSIM web interface will verify it in the window: **Configuration-> Plugins**

![alt text](http://i.hizliresim.com/0D60m9.jpg "OSSIM Logo")

Modification of the values in the above illustration for reliability and priority for each plugin_sid,
requires restart of the OSSIM server in order for it to take effect. 

##Agent Configuration
The following steps detail configuration of the agent for the plugin. This plugin is going to monitor
syslog for the output, so a config file for the plugin  must exist containing the plugin ID and how to
match information in syslog. In this case, it matches only one sid, but as you can see from the above sql,
there could be five patterns and five sub ids. 

Contents of /etc/ossim/agent/plugins/foobar.cfg You can copy and paste into the shell. If you create the
file manually, be sure to remove the backslashes before any ‘$’ symbol. 

```
<localfile>
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

</localfile>
```

We need to tell the agent that we have a new plugin. Edit the file /etc/ossim/agent/config.cfg and add
the following line in the [plugin] section.

```
<localfile>
foobar=/etc/ossim/agent/plugins/foobar.cfg
</localfile>
```
Now to restart the agent so that it is aware of the new plugin information. 
```
<localfile>
/etc/init.d/ossim-agent restart
</localfile>
```

##Verification
This is a sample python script that will send a message to syslog. I parses the optios sent and sends a
log message for each option that matches the case. The following code can be run as a script on any
host that has Python installed.

```
<localfile>
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
</localfile>
```

Run this program on the server for which you want to generate the event. The following will send the
first type syslog message. 

```
<localfile>
testfoobar.py 1
</localfile>
```
The second will send the 5th type syslog message, the 4th type syslog message, and then finally the 2nd
type syslog message. 

```
<localfile>
testfoobar.py 5 4 2
</localfile>
```

Check your events and alarms. An event and/or an alarm should appear on the event tab previously
shown.


#A Sample OSSIM directive
OSSIM stores its rules on the server in a file named /etc/ossim/server/directives.xml. The rules are
separated into directives. The following is an example ssh brute force directive. This rules from this
directive obtains its information from the ssh auth.log plugin. In this case, the attacker could be
switching different hosts to attack in attempt to escape detection on a single host, but this directive will
detect those attempts between switched target hosts as well. The reliability begins at 3 after three failed
attempts. Three more will raise it to 4. Five more will raise it 6, and then an additional 10 attempts will
raise it to 8. 

```
<localfile>
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

</localfile>
```


#OSSIM ARCHITECTURE
![alt text](http://i.hizliresim.com/7vnaRl.jpg "OSSEC Logo")

![alt text](http://i.hizliresim.com/PMW1X8.jpg "OSSEC Logo")

![alt text](http://i.hizliresim.com/go0rmN.jpg "OSSEC Logo")



#Logging in
OSSIM konsolu web üzerine kurulmuş olup, standart bir web tarayıcısı üzerinden 80 portundan (HTTP) veya güvenli olan 443 portundan (HTTPS)'den bağlanılabilir.

* Kullandığımız browser'ı açıyoruz.
* Addres yerine **http://ipaddressorofossimserver** yazıyoruz.
* OSSIM ID kullanıcı adımızı yazıyoruz.
* OsSIM şifresini giriyoruz. 


Default şifremizi değiştirmeyi unutmuyoruz ve buna özen gösteriyoruz.

Bir kere giriş yaptıktan sonra, Karşımıza **Metrics** ekranı gelmektedir. Metrics ekranın da ise izlemek istediğimiz Network'leri gözden geçiriyoruz. 

##The Metrics Screen 
![alt text](http://i.hizliresim.com/7vnB9N.jpg "OSSEC Logo")

Göründüğü gibi ekran farklı bölümlere ayrılmıştır. Bunlar **Global Metrics**, **Riskmeter**, **Service Level**, ve  policy'nin her bir parçası için **Current Metrics**.

#The Policy Menu
OSSIM Policy menüsü yönetciye, policy inşaa etmek için gerekli olan objeleri yaratmaya ve bunları değiştirmeye izin verir.


##Creating a new sensor
Aşağıda takip edilen adımlarla, yönetici bir OSSIM sensör ekleyebilir veya bunu değiştirebilir.
* **policy**'e tıklıyoruz.
* **sensors**Ee tıklıyoruz.

Karşımıza şu ekran çıkıyor. Burda farkettiğiniz üzere bu sensör önceden eklenmiştir.


![alt text](http://i.hizliresim.com/PMW78O.jpg "OSSEC Logo")

* **Insert new sensor**'e tıklıyoruz.
* 
Karşımıza şu ekran çıkacaktır. 

![alt text](http://i.hizliresim.com/go0PdO.jpg "OSSEC Logo")


* Add the Hostname - Host'unuzun ismi
* Add the IP Address - Host'un IP numarası.
* Add the Priority - Host'un ne kadar önemli olduğu ve önceliği. 5 en fazla öneme tekabül etmektedir.
* Add the Port - Serverin hangi port'una bağlı olacağına
* Add the description - Açıklama.

Objeyi oluşturmak için **OK**'a tıklıyoruz. Sensor yaratıldığında Sensorler ekranında eklemiş olduğumuz bilgileri görebiliyoruz.

![alt text](http://i.hizliresim.com/9L1YMN.jpg "OSSEC Logo")

Eğer eklenmiş yeni sensör aktif değilse, Aktif butonuna basarak bağlantıyı tekrar kontrol ediyoruz.

##Defining Signature groups
İmzalar bölümü direkt olarak Snort ve sensörden okunan diğer imzala tipleriyle alakalıdırlar. Buradaki birbirinden bağımsız uyarılar 
ACID başlığı altında incelenebilirler. Bu bölümde yönetici, saldırılarla ilgili olan imzaları optimise edebilir. Bu bölüm Diğer sensörler için diğer imzaların açıklamalarını da taşıdığı için oldukça kullanışlı bir bölümdür. Örneğin, sadece Snort Virüs rules içeren Virüs tiplerinin imza listesi tutulabilir. 

Yeni bir imza grubu oluşturmak için:
* **Policy**'e tıklıyoruz.
* **Signatures**'a tıklıyoruz.
* **Insert new signature group**'a tıklıyoruz.

![alt text](http://i.hizliresim.com/qBkA6d.jpg "OSSEC Logo")


Karşımıza şu ekran çıkıyor.

![alt text](http://i.hizliresim.com/MJG1N1.jpg "OSSEC Logo")


Burada bir imza grubuna isim verebiliyoruz. Açıklamak istediğimiz imzaları seçiyoruz.
* Anlamlı olan kutulara tıklıyoruz.
* Kullanışlı bir açıklama ekliyoruz.
* **OK** butonuna basıyoruz.

Yeni imza eklenmiş oldu. İleride policy yaratman için kullanılmaya hazırdır.

##Creating a Network
Genellikle Network gruplarının organizasyonu elimizde bulundururuz. Bunun için **The Policy >
Networks** Butonuna basıyoruz.
Karşımıza şu ekran çıkıyor.

![alt text](http://i.hizliresim.com/QM3PDy.jpg "OSSEC Logo")


Yeni bir Network eklemek için 
* **Insert new network**'e basıyoruz. 

![alt text](http://i.hizliresim.com/X41bV3.jpg "OSSEC Logo")


Aşşağıdaki bileşenleri sırayla ekliyoruz.
* Name - Yeni Network veya Network grubunun ismi 
* Ips - Networklerin IP adresleri 
* Priority - Eklenilen Network'ün ne kadar önemli olduğunu belirtiyoruz. 5, en yüksek dereceye tekabül ediyor.
* Threshold - Alarmın verilmesiyse ilgili Thresholds değeri.
* Sensors - Hangi sensörün bu Network'ü izleyeceği.
* Scan options - Zayıflıkların taranıp taranmayacağına karar verildiği yer.
* Description - Network grubunun açıklaması.

 **OK** tuşuna basıyoruz ve  to Network grubu ekleniyor.
 **NOT:** Her bir Network grubunun periyodik olarak taranmasını istemiyorsak, Nessus Scan seçeneğini **DISABLED** yapmalıyız.

## Adding a group of relevant ports
Bazı zamanlarda, OSSIM'in izlemesi gereken portların optimise edilmesi veya değiştirilmesi gerekmektedir. Bunu yapmak için de **Policy >Ports** Menüsüne giriyoruz.
Yeni bir port grubu oluşturmak için aşşağıdaki adımlara harfi harfine uymamız gerekiyor.

* **Policy**'ye tıklıyoruz
* **Ports**'a tıklıyoruz.
* **Insert new Port Group**'a tıklıyoruz
* Bu port grubu için bir isim ekliyoruz
* İzlemek istediğimiz portları seçiyoruz
* Açıklama ekliyoruz
* Son olarak **OK** butonuna basıyoruz.

Yeni port grubu aşşağıda görüldüğü gibi eklenmiş bulunuyor.

![alt text](http://i.hizliresim.com/bbXvqZ.jpg "OSSEC Logo")


##Editing the Priority & Reliability

OSSIM'de öncelik ve güvenilirliği Network'de alınan imzalar doğrultusunda değiştirilebilme imkanı vardır. Bu durum gerçektende yönetici için çok yararlı bir durumdur. Çünkü, yönetici bizi imzanın zayıflığı konusunda bizi uyarabilme şansına sahip olur.

Güvenilirliği ve önceliği değiştirmek için:
* **Policy**'e tıklıyoruz
* **Priority & Reliability**'e tıklıyoruz

Karşımıza çıkan ekran şu olacaktır.

![alt text](http://i.hizliresim.com/dbdLQD.jpg "OSSEC Logo")



Back Orifice'nin öncelik ve güvenilirliğini değiştirmek için,  **Id** alanına tıklıyoruz.

Aşağıda gördüğümüz ekran görütüsünde gördüğümüz üzere, Back orifice en yüksek önceliğe sahip. Güvenilirlik derecesi de 3'e set edilmiştir bunu değiştirmek içinde farklı bir değer girip **Modify** butonuna basılmalıdır.

![alt text](http://i.hizliresim.com/EJd2bv.jpg "OSSEC Logo")


Yukarıdaki görev OSSIM'i kendi network'ümüze göre optimize ettiğimizde, OSSIM tarafından üstlenilmiş bir görev olacaktır.


##Creating a Host
Önceki adımları tamamlamak için son işlemimiz diyebiliriz. Yeni bir host oluşturmanın iki farklı yolu vardır. Ya manuel bir şekilde ya da bilinen bir hostun networkde scan edip o host hakkında bilgi alınması şeklindedir.

**Policy > Hosts** menü, Host operating system şeklinde P0F kullanarak detect edilmesi aşağıdaki şekildedir. 

![alt text](http://i.hizliresim.com/jnOAL9.jpg "OSSEC Logo")


Yeni bir host eklemek için

* **Insert new host**'a tıklıyoruz.
* Aşağıda görülen tüm yerlere anlamlı bilgileri giriyoruz.

![alt text](http://i.hizliresim.com/2Z3PyL.jpg "OSSEC Logo")


**Önemli : Burada Nessus scan'i akif etmeliyiz. Bu durumda large bir network kullanıyorsak bütün zayıf noktaları görmemize gerek kalmaz. Asıl yapılması gereken, belirli olarak seçeceğimiz bir hostta zayıflıklar var mı yok mu görmek daha faydalı olacaktır.**

Gerekli bilgiler doldurulduğunda **OK** butonuna basılmalıdır. Bu yeni host, host listesinde yer alacaktır. Eğer gilgiler yanlış yazılmış ise **Modify** Butonunu kullanarak, bu bilgiler tekrardan değiştirilebilir.

### Updating and the host information.
Yeni bir host'un bilgilerini update etmek için, **Host Field** kısmından bilgileri değiştirilmek istenen host ismine tıklanır. Ve karşımıza şu şekilde bir ekran çıkacaktır.

![alt text](http://i.hizliresim.com/B2QGEV.jpg "OSSEC Logo")


Host inventory'sini update etmek için **update** butonuna basılır. Yeni hostlara karşı Nmap scan başlatılır. Bu durum açık portları elde etmemize yararken, servis sistemde aşağıdaki gibi çalışmaktadır.

![alt text](http://i.hizliresim.com/ZdBnLg.jpg "OSSEC Logo")


Spesifik bir host için **Metrics**'i incelemek için, **Metrics** Butonuna basılmalıdır. Karşımıza çıkacak olan Metrics grafiği atakları gösterir. Bu grafik gün bazında, ay bazında olacağı gibi yıl bazında da olabilir.

![alt text](http://i.hizliresim.com/o7WyAQ.jpg "OSSEC Logo")


### Alarms and Alerts
Host Report menüsünde 3 tane alt bölüm bulunmaktadır. Bunlar; **Vulnerabilities**, **Alarms**, ve **Alerts** dir. Peki alarm ve Alert arasındaki fark nedir?

Belirli olan belli başlı kriterler sağlandığında alarm ortaya çıkar. Örneğin, şu durumlar gerçeleştiğinde alarm ortaya çıkar

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

![alt text](http://i.hizliresim.com/l1G4kB.jpg "OSSEC Logo")


###Using the ACID console.
ACID çok önemli bir araç olup ihlalleri tespit edip bununla ilgili bilgileri kullanıcıya verir.
OSSIM'le ilgili oldukca da bağlantılı olup daha fazla bilgiyi **http://acidlab.sourceforge.net** sayfasından elde edebilirsiniz. 

Aşağıda ACID'in basit bir örneklendirmesini görebilirsini görebilirsiniz.

Saldırıların oluşumuna bakmak için **Occurances as Src.** kısmına tıklanmalı ve detect edilen imzalar ve saldırılar görülebilir.

![alt text](http://i.hizliresim.com/VYnBly.jpg "OSSEC Logo")


Herhangi bir imza ile ilgili daha fazla bilgi almak için **[snort]** üzreine tıklanmalı ve bu bizi Snort rules tanımlarının olduğu sayfaya yönlendirecektir. Bu sayfada imza ile ilgili önemli bilgiler yer almaktadır.

### Vulnerabilities
OSSIM, şirketlere ve bireysel kullanıcılara kendi serverlerindeki önde gelen zayıf noktaları inceleme imkanı sağlar. Bunu sağlayan **Host Repot** menüsüdür. Bu bölüm zayıf noktaların raporlarını elde eder ve bu noktaları tarar. Bunun sonucunu da görmek için önce **Vulnmeter** başlığı altındaki **Vulnerabilities** bölümüne bakmamız yeterli olacaktır.

Bu bölümde zayıf noktaları olan hostların listesi gelecektir. ve ilgili host ve ilgili IP adress highlighted şekilde gözükecektir. Üzerinde çalışılmak istenen host ve IP adresin üzerine tıklanması gerekir.

![alt text](http://i.hizliresim.com/nr6yA5.jpg "OSSEC Logo")


Daha fazla bilgi edinmek için **(Security hole found)** seçeneğine tıklanmalı ve scroll bar aşağı indirilmelidir.

### Host Usage
Host usage ile ilgili bilgiler **NTOP** tarafından sağlanmaktadır. Daha fazla bilgiyi **http://www.ntop.org.** adresinden elde edebilirsiniz. Trafik akışındaki şüpheli durumlar içn OSSIM, NTOP'u kullanmaktadır.

![alt text](http://i.hizliresim.com/v42ygm.jpg "OSSEC Logo")


### Anomalies
Anomalies host'un normal davranışının değişmesidir. Bu bölümde **işletim sistemi** ve **MAC adresi** değişmelerini içermektedir. Anomalie'ler, yaratılmış olan RDD_Config'e göre değişiklik gösterirler. Bütün anomalie'leri görmek için **Control Panel > Anomalies**
bölümüne girilmelidir. Sonradan karşımıza şu ekran çıkacaktır.

![alt text](http://i.hizliresim.com/R3ZGkG.jpg "OSSEC Logo")


Değişiklikler farkedilebilir ya da görmezden gelinebilir.

## Creating a Policy

Policy yaratmak, OSSIM için en önemli durumlardan biridir. Çünkü, yaratılan policy ile hostların ve networklerin izlenme işlemleri yapılır. Buna göre de anlamlı ve istenilen bilgiler elde edilir.

* **Policy**'ye tıklıyoruz.

Aşşağıdaki resimde, gösterilen network için bir kaç tane hali hazırda varolan policy olduğunu görüyoruz.

![alt text](http://i.hizliresim.com/pP32zN.jpg "OSSEC Logo")


Yeni bir policy eklemek için, **Insert new policy**'a tıklanır. Sonrasında karşımıza şu ekran çıkar.

![alt text](http://i.hizliresim.com/kvz0B7.jpg "OSSEC Logo")


* Source addressler seçilir.
* Destination addressler seçilir.
* Portlar seçilir
* Priority seçilir
* İmzalar seçilir
* Bu policy'de hangi sensörün çalışması istendiği bilirlenir
* Time range belirlenir.
* Policy için bir tanım verilir
* Kaydedilmesi için **Ok** tuşuna basılır. 

# Reports
Reports, OSSIM'in sağladığı hostlar ve tüm network güvenliği için bilgi edinilmesini sağlayan bir menüdür. Gelen report'lar isteğe göre değiştirilebilir ve hangi raporların görülüp görülmeyeceğini kullanıcı tarafından seçilebilir.

The Security Report bölümü aşşağıdaki bilgileri sağlar. 

![alt text](http://i.hizliresim.com/NEBGAN.jpg "OSSEC Logo")


 **Top 10 Alerts**'a tıkladığımızda, karşımıza şu ekran çıkacaktır.

![alt text](http://i.hizliresim.com/aEQg3R.jpg "OSSEC Logo")

Ayrıca bu ekranda, verilem alert'ler hakkında bilgi edinebildiğinden oldukça kullanışlı bir bölümdür. Ayrıca görünmesini istemediğimiz alert'ları bu menüdeyken silebiliriz.

# Monitors Menu

Bu bölümde Session, Network, Availability ve Riskmeter gibi alt başlıklar yer almaktadır.
Monitor menüsü  real-time network, uptime, ve risk session data gibi seçenekleri sağlar. Bu bölümdeki bilgilerin çoğunu NTOP ve OpenNMS sağlar.

* NTOP – http://www.ntop.org
* OPENNMS – http://www.opennms.org

##RiskMeter 

![alt text](http://i.hizliresim.com/YbLVka.jpg "OSSEC Logo")

Riskmeter risk altında olan veya saldırı gerçekleştirilen sistem hakkında bilgi edinilmesini sağlar. Bu riskmeter'in nasıl hesaplandığını öğrenmek için OSSIM websitesini ziyaret edebilirsiniz http://www.ossim.net. 

#Configuration Menu

Configuration menüsü, yöneticiye Ossimin seçeneklerini değiştirme imkanı sağlar. Sub menüler ise reload all policies, edit directives , view correlation, information, create or modify RDD_Config information, add a host to scan, and edit the global riskmeter configuratin gibi seçenekleri içermektedir.

##Sub Menus

###Main

Main menü' de bir çok ayrı ayrı parçalar bulunmaktadır.

![alt text](http://i.hizliresim.com/81vXZr.jpg "OSSEC Logo")


### Directives

Directives dediğimizde alarm'a neden olan olayların hepsi olarak düşünebiliriz. Bu durumlar herhangi bir altyapıya göre optimise edilebilir. Aşşağıdaki ekran görüntünsünde, win-trin00 Trojan'ı için default directive görünmektedir.


![alt text](http://i.hizliresim.com/DJbG21.jpg "OSSEC Logo")


Directive'ler plugin ID'ler tarafından değiştirebilirler. Örneğin, Ossime tıklayıp karşımıza şu ekran çıktığında, bu ekranda yöneticiye öncelik ve güvenlik olan OSSIM durumlarını değiştirme imkanı veriyor.

![alt text](http://i.hizliresim.com/mLyR6y.jpg "OSSEC Logo")


### RRD Configuration
RDD biçimlendirme, alınmak istenen uyarılar için yönetecinin anlamlı değerler ve de thersholds değerlerini girmesini sağlar.
Aşağıdaki örnekte default RDD_Config ve deafult seçenekler mevcut. Fakat, farklı bir RDD configuration ekleyebiliriz. Bu da aşşağıda şekildeki gibi olmaktadır.


####Yeni Bir RRD Configuration Ekleme. 

![alt text](http://i.hizliresim.com/EJd289.jpg "OSSEC Logo")


* **Configuration > RRD_Config**'a tıklıyoruz.
* **Insert new rrd_conf**' a tıklıyoruz.

Karşımıza çıkan ekranda, biçimlendirilmesine izin verilen bireysel network'ler veya host'lar görünüyor.


* Monitor'e bir IP addresi ekliyoruz.
* thresolds değerini aşağıdaki ipucu değerlerine göre değiştiriyoruz.

![alt text](http://i.hizliresim.com/ZdBnZZ.jpg "OSSEC Logo")


## Host Scan
Host scan seçeneği kullanıcıya scan edilecek olan host listesine, scan edilmesi istenen host'un eklenmesini sağlar. Bu çok tercih edilen bir yöntem değildir. Bunun yerine **Policy > Hosts > Insert new host** menüsünden bu seçeneği eklemek daha iyi bir fikir olur.


##Riskmeter configuration
Aşağıdaki screenshoot'dan görüleceği gibi, default configuration **Configuration > Riskmeter** bölümünden değiştirilebilir.

![alt text](http://i.hizliresim.com/o7Wyjk.jpg "OSSEC Logo")


# Tools
Tools menüsüne tıklandığında Scan host, view alarm backlog ve view rules gibi seçenekleri görürüz.


## Scan
Scan seçeneği tanımlanmış Network range'indeki tüm ip adresslerini tarar. Bu sayede, hangi host'un çalışıp çalışmadığı hakkında bilgi verir. Belli bir range'yi taramak için aşağıdaki range belirlenmeli ve **OK** tuşuna basılmalıdır.

![alt text](http://i.hizliresim.com/l1G4db.jpg "OSSEC Logo")


## Backlog Viewer

Backlog viewer, öne çıkan anormallikler hakkında bilgi edinilmesini sağlar.


## Rule viewer

Rule viewer, yöneticiye kuralları ayrı ayrı gösteren bir paneldir.  **Tools > Rule
Viewer** butonuna tıkladıktan sonra , incelenmek istenen kural seçilir. Aşşağıdaki durumda virüsle ilgili olan kural yer almaktadır.

![alt text](http://i.hizliresim.com/VYnB0r.jpg "OSSEC Logo")

