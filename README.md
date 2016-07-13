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
The OSSIM console is web based, and can be interfaced through any standard web browser. The
system runs on port 80 (HTTP) or secure (HTTPS) port 443.

* Start your favourite browser.
* In the address bar enter – http://ipaddressorofossimserver
* Enter the user ID ossim
* Enter the password ossim_password 


Remember to change your password from the default.

Once you have logged in, you will be presented with the Metrics screen. The Metrics screen
provides an overview of what is going on in the networks you have decided to monitor. 

##The Metrics Screen 
![alt text](http://i.hizliresim.com/7vnB9N.jpg "OSSEC Logo")


The screen is split into separate sections. Global Metrics, Riskmeter, Service Level, and current
metrics for each of the individual components you have defined as part of a policy. 

#The Policy Menu
The OSSIM policy menu allows an administrator to create, or modify the objects needed to build a
policy.


##Creating a new sensor
The following steps allow an administrator to add or modify an OSSIM sensor.
*Click on **policy**
* Click on **sensors**
You should be presented with the following screen. Note – This is a sensor we installed earlier. 


![alt text](http://i.hizliresim.com/PMW78O.jpg "OSSEC Logo")

* Click **Insert new sensor**.
You will be presented with the following screen. 

![alt text](http://i.hizliresim.com/go0PdO.jpg "OSSEC Logo")


*Add the Hostname - Name of your host
*Add the IP Address - IP of the host.
*Add the Priority - How important this host is. A priority of 5 is most important.
*Add the Port - Which port the server connects on.
*Add the description - The description.

Click **OK** to create the object. Once the sensor has been created you should see the following updated
information on the sensors screen. 

![alt text](http://i.hizliresim.com/9L1YMN.jpg "OSSEC Logo")


If the new sensor does not appear as active, click the Active button to recheck the connection. If this
is still not active please refer to the OSSIM or Boseco forums. 

##Defining Signature groups
The signatures section relates directly to the snort, and other signatures types that are picked up by the
sensor. These individual alerts can be viewed in ACID. In this section the administrator can optimise
the amount of attack signatures or responses of that are of interest. This section is useful as it allows
the definition of different signatures for different sensors. So, for example, we can define a signature
list of type Virus that only contains the Snort Virus rules for the internal network, but a different list
of Web server signatures for the DMZ.
To create a new signature group:
* Click on **Policy**.
* Click on **Signatures**.
* Click **Insert new signature group**.

![alt text](http://i.hizliresim.com/qBkA6d.jpg "OSSEC Logo")


The following screen appears. 

![alt text](http://i.hizliresim.com/MJG1N1.jpg "OSSEC Logo")


From here, give the new signature group a name, and choose the signatures that you wish to define.
* Tick the relevant boxes.
* Add a useful description.
* Click **OK**
The new signature is now added, and available for use in future policy creation. 

##Creating a Network
It is very likely that you will need to define multiple networks within the organisation. **The Policy >
Networks** option allows us to do this. Click **Policy > Networks**. You will be presented with the
following screen. 

![alt text](http://i.hizliresim.com/QM3PDy.jpg "OSSEC Logo")


To add a new network, click on:
* **Insert new network**. 

![alt text](http://i.hizliresim.com/X41bV3.jpg "OSSEC Logo")


Add the following components.
* Name - Name of the new network/networks group.
* Ips - IP addresses of the networks
* Priority - How important is this network. A priority of 5 is most important.
* Threshold - The thresholds for this network before raising an alarm.
* Sensors - Which sensors monitor this network.
* Scan options - Tick this if you would like the network scanned for vulnerabilities.
* Description - Network group description.

Click **OK** to add the new network group.
Please note: If you do not wish to have the entire network group scanned periodically, ensure that the
NESSUS SCAN option is set to **DISABLED**. 

## Adding a group of relevant ports
It may be necessary from time to time for the administrator to optimise the ports OSSIM should
monitor. This is done through the **Policy > Ports** menu option.
To define a new group of ports, complete the following tasks.
* Click on Policy
* Click on Ports
* Click Insert new Port Group
* Add a name for the port group.
* Tick the ports that you wish to monitor.
* Add the description.
* Click **OK**.

The port group has now been added, as shown below

![alt text](http://i.hizliresim.com/bbXvqZ.jpg "OSSEC Logo")


##Editing the Priority & Reliability
With OSSIM, it is possible to change the priority and reliability rating of signatures detected on the
network. This is an extremely useful facility as it gives the administrator the ability to reduce the
amount of false positives, or alert you to one specific signature type you may know you are vulnerable
to.
To change the priority and reliability settings:
* Click **Policy**
* Click **Priority & Reliability**

You will see the following screen. 

![alt text](http://i.hizliresim.com/dbdLQD.jpg "OSSEC Logo")



To edit the priority and reliability of Back Orifice, click on the **Id** field.

As can be seen from the screenshot below, Back Orifice has the highest priority for obvious reasons.
The reliability of the Back Orifice signature has been set to 3. We can change this by simply editing
the number 3, and increasing or decreasing the number. Once this is complete, click Modify. 

![alt text](http://i.hizliresim.com/EJd2bv.jpg "OSSEC Logo")



The above task will be undertaken on a regular basis as you optimise OSSIM for your network. 

##Creating a Host
Finally, once all of the previous steps have been completed, a host may be added. It was necessary to
complete the previous steps, as all of them provide the information required for the host entry.
There are two ways to create a new host. Manually, and with a scan, which will provide information
on hosts that are live on the network. We are going to undertake a manual installation through the
**Policy > Hosts** menu. Host operating system types shown below are detected using P0F. 

![alt text](http://i.hizliresim.com/jnOAL9.jpg "OSSEC Logo")


To add the new host:
* Click **Insert new host**
* Add information to all of the sections shown in the screenshot on the following page. 

![alt text](http://i.hizliresim.com/2Z3PyL.jpg "OSSEC Logo")


**IMPORTANT : Enable nessus scan. You may not always wish to look for vulnerabilities if you
have a large network. Ticking ‘Enable nessus scan’ will add the host to the scheduled scans.
Network utilisation on large networks may reach undesirable levels. Choose the hosts you wish
to scan for vulnerabilities carefully.**

Once the information has been inserted, click **OK**. The new host will appear in the hosts list.
More information about the individual host can now be determined. If the information entered is
incorrect, clicking on Modify, in the Action column, and editing the information can change it.

### Updating and the host information.
To update the new host information click on the hosts name in the Hostname field.
You will be presented with the following screen.

![alt text](http://i.hizliresim.com/B2QGEV.jpg "OSSEC Logo")


Update the host inventory information by clicking **update**. The update facility initiates an Nmap scan
against the new host. This will obtain the open ports, and the services running on the system, as
shown below.

![alt text](http://i.hizliresim.com/ZdBnLg.jpg "OSSEC Logo")


To view the **Metrics** for a specific host, click on the **Metrics** button. The metrics graphs show
Attacks, and Compromises picked up against the relevant host. The graphs are based on the last day,
week, month or year. 

![alt text](http://i.hizliresim.com/o7WyAQ.jpg "OSSEC Logo")


### Alarms and Alerts
On the Host Report menu, there are three sub-sections. Vulnerabilities, which we will look at further
on in this document is one. The other two are Alarms, and Alerts. So what is the difference between
the two latter sections?
Alarms are raised when a set of criteria has been met based on the directives created. For example, an
alarm may trip if the following group of events occur together.
* An alert is produced by Snort.
* A specific attack response is detected relevant to the alert.
* Specific thresholds have been passed.
* An attack has lasted for a designated length of time.
* The priority of the system is high enough.

All of the above are added together to create an alarm. This system is designed to limit the false
positives produced by the system

Alternatively, an alert is raised when Snort, or Spade detects a specific attack signature. This is
shown in **ACID** – **A** **C**onsole for **I**ntrusion **D**etection, which will be explained on the next few pages
of this document.

Alarms options are Source or Destination, Source, Destination.
Alerts options are Main, Source, and Destination

Clicking on any of the above options in Alarms will provide the Alarms relevant to the host. 

###Alerts
The Alerts view is obtained through ACID. To enter the acid console, a user ID and password are
required.

* Click on **Main**.

You will be presented with a login box. The default USERID and PASSWORD are shown below.

USER ID: acid
PASS: acid_password

It is advisable to change these passwords during the installation and configuration phase of OSSIM.
As mentioned earlier, documentation pertaining to the installation can be found on
http://www.ossim.net

Once successfully logged in, the administrator is presented with the following screen. 

![alt text](http://i.hizliresim.com/l1G4kB.jpg "OSSEC Logo")


###Using the ACID console.
ACID is a very powerful tool for examining intrusion detection information. As this is a user manual
specifically related to OSSIM, and although we touch on the underlying utilities, each of these utilities
may have its own user manual. More information, including a FAQ for ACID can be found at –
http://acidlab.sourceforge.net

Below is a basic demonstration of the information available via ACID.

To look at the occurrences of attacks as source from the designated system click the number in the
**Occurances as Src.** field. The following screen will appear with the signatures/attacks detected. 

![alt text](http://i.hizliresim.com/VYnBly.jpg "OSSEC Logo")


For further information on any of the signatures, click on **[snort]**. This will take you to the Snort rules
descriptions page, which will give you relevant information on the signature, including the potential
for false positives and false negatives. As mentioned earlier ACID is a powerful tool, which can also
perform graphing functions. It is recommended therefore that anyone wishing to use OSSIM to its
full potential should also have a good understanding of ACID, as well as the other underlying utilities.

### Vulnerabilities
OSSIM allows companies or individuals to view the vulnerabilities currently outstanding on their
servers. This is done from the same Host Report menu. To obtain a vulnerability report, a Nessus
scan against the host must be undertaken. Once this has been completed, click on **Vulnmeter**, under
the **Vulnerabilities** section of the Host Report menu to view the results.

A list of hosts with vulnerabilities is provided. The relevant host, and its IP address are highlighted in
red. Click on the IP address of the host you wish to study.

![alt text](http://i.hizliresim.com/nr6yA5.jpg "OSSEC Logo")


To view further detail on any security holes found, and to determine whether it is a relevant
vulnerability, click on **(Security hole found)**. Or scroll through the report. 

### Host Usage
The Usage information is provided by **NTOP**. Further information on NTOP is available from –
http://www.ntop.org. OSSIM uses NTOP to look at traffic flows including suspicious traffic. 

![alt text](http://i.hizliresim.com/v42ygm.jpg "OSSEC Logo")


### Anomalies
Anomalies are changes in the usual behaviour of the host. This section defines such things as
operating system or MAC address changes. The anomalies are based on the RRD_Config that is
created. An overall list of anomalies can be viewed using the **Control Panel > Anomalies** section as
show in the following screenshot. 

![alt text](http://i.hizliresim.com/R3ZGkG.jpg "OSSEC Logo")


The changes can be acknowledged or ignored.

## Creating a Policy
The most important thing that has to be created in OSSIM is a policy for the monitoring of networks
and hosts. Now that all the relevant information has been entered for the networks and hosts within
the organisation, it is possible to create policies relevant to those.
* Click on Policy
* Click on Policy
The following screen is shown. Notice that a few policies already exist for the example network. 

![alt text](http://i.hizliresim.com/pP32zN.jpg "OSSEC Logo")


To add a new policy, click **Insert new policy**. You are presented with the Insert new policy screen. 

![alt text](http://i.hizliresim.com/kvz0B7.jpg "OSSEC Logo")


* Choose the source addresses.
* Choose the destination addresses
* Choose the ports
* Choose the priority
* Choose the signatures.
* Choose the sensors you wish to use with this policy
* Choose the time range.
* Enter a description for the policy.
* Click OK to save. 

# Reports
The Reports section of OSSIM provides information on both hosts, and overall network security. The
host report option provides an alternative way of obtaining the host data we touched on earlier in this
document.
The Security Report section provides the following information. 

![alt text](http://i.hizliresim.com/NEBGAN.jpg "OSSEC Logo")


Clicking on Top 10 Alerts, will provide the following screen.

![alt text](http://i.hizliresim.com/aEQg3R.jpg "OSSEC Logo")


It is also possible, from this menu, to drill further into each individual alert using ACID. This screen
is extremely useful for the purposes of removing false positives, or optimising the Snort sensors to
remove an alert you do not wish to see. 

# Monitors Menu
Session, Network, Availability, and Riskmeter are sub-menus provided in this section.
The monitor’s menu provides real-time network, uptime, and risk session data. NTOP and OpenNMS
provide most of the information shown in this section. To fully appreciate the information provided
in these sections, and to obtain the in-depth documentation, please visit the relevant websites.
* NTOP – http://www.ntop.org
* OPENNMS – http://www.opennms.org

##RiskMeter 

![alt text](http://i.hizliresim.com/YbLVka.jpg "OSSEC Logo")


The Riskmeter provides information pertaining to the systems, which are currently deemed to be at
risk, or are currently launching attacks. For a definition of risk pertaining to OSSIM, and how it is
calculated, please see the OSSIM website at http://www.ossim.net. 

#Configuration Menu

The configuration menu provides the administrator with the ability to change and optimise OSSIM
settings. The sub-menus include options to reload all policies, edit directives, view correlation
information, create or modify RRD_Config information, add a host to scan, and edit the global
riskmeter configuration. 

##Sub Menus

###Main

The Main menu allows the user to reload individual components, or all components. 

![alt text](http://i.hizliresim.com/81vXZr.jpg "OSSEC Logo")


### Directives

Directives are a set of events that combine to cause an alarm. These events can be optimised to suit
any infrastructure. The screenshot below shows the default directive for the win-trin00 Trojan. 

![alt text](http://i.hizliresim.com/DJbG21.jpg "OSSEC Logo")


The directives can be edited by clicking on the relevant plugin ID. So, for example we can click on
ossim and the following screen is presented, which allows the administrator to edit the priority and
reliability of OSSIM events. 

![alt text](http://i.hizliresim.com/mLyR6y.jpg "OSSEC Logo")


### RRD Configuration
The RRD config allows the administrator to enter relevant values and thresholds for alerting. An
example of this is shown below. A default global RRD_Config, with default settings exists, but new
RRD configurations can be added for individual hosts, or networks.
A new RRD configuration is added in the following way.

####Inserting a new RRD Configuration. 

![alt text](http://i.hizliresim.com/EJd289.jpg "OSSEC Logo")


* Click on **Configuration > RRD_Config**
* Click on Insert **new rrd_conf**

The following screen appears, which will allow configuration of an individual network or host.

* Add an IP Address to monitor.
* Edit the thresholds based on the hints below. 

![alt text](http://i.hizliresim.com/ZdBnZZ.jpg "OSSEC Logo")


## Host Scan
The host scan option allows the user to add a host to a list of hosts to scan. It is not advisable to do
this. Instead, it is a better idea to add the options via the **Policy > Hosts > Insert new host** menu
option. 

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

