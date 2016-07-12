# OSSIM_Kullanim Kılavuzu
OSSIM(Meaning Open Source Security Information Manager) is an open source project by Alienvault which provides the SIEM (Security information and event management) functionality. It provides SIEM features which are required by security professionals. The goal of OSSIM is to fill a gap in the needs of security professionals.

Considering the important technological advances of recent years that have made tools with capacities
such as those of IDS available, it is surprising that it is so complex from a security standpoint to
obtain a snapshot of a network as well as information with a level of abstraction that allows practical
and manageable monitoring. 


![alt text](http://cybersecurity-excellence-awards.com/wp-content/uploads/2016/01/638669-500x318.jpg "OSSIM Logo")

#CORRELATION
Correlation means the ability to view all events in all systems in one place and in the same format,
and from this privileged vantage point compare and process the information, thereby allowing us to
improve detection capabilities, prioritise events according to the context in which they occurred, and
monitor the security situation of our network.
The idea of correlation is also implicit in the vision of our project in the sense of bundling and
integrating products. Within the general framework of OSSIM, we want to include a number of
magnificent products developed in recent years that create new possibilities when their functionalities
are interrelated. 

#RISK ASSESSMENT
In each case, in order to decide whether or not to perform an action we evaluate the threat represented
by an event in relation to certain assets, keeping in mind the reliability of our data and the probability
the event will occur.
This is where the system becomes more complex, and we must therefore be able to implement a
security policy, a network inventory, a real-time risk monitor-all configured and managed within a
single framework... In any case, we cannot let complexity keep us from achieving our objective:
product integration


#WHAT IS OSSIM?
OSSIM is a distribution of open source products that are integrated to provide an infrastructure for
security monitoring.
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

#Installation and Configuration of OSSIM
Coming soon.

#Logging in
The OSSIM console is web based, and can be interfaced through any standard web browser. The
system runs on port 80 (HTTP) or secure (HTTPS) port 443.

* Start your favourite browser.
* In the address bar enter – http://ipaddressorofossimserver
* Enter the user ID ossim
* Enter the password ossim_password 

FOTO GELİCEK


Remember to change your password from the default.

Once you have logged in, you will be presented with the Metrics screen. The Metrics screen
provides an overview of what is going on in the networks you have decided to monitor. 

##The Metrics Screen 

FOTO GELİCEK 

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

FOTO GELİCEK

* Click **Insert new sensor**.
You will be presented with the following screen. 

FOTO GELİCEK

*Add the Hostname - Name of your host
*Add the IP Address - IP of the host.
*Add the Priority - How important this host is. A priority of 5 is most important.
*Add the Port - Which port the server connects on.
*Add the description - The description.

Click **OK** to create the object. Once the sensor has been created you should see the following updated
information on the sensors screen. 

FOTO GELİCEK

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

FOTO GELİCEK

The following screen appears. 

FOTO GELİCEK

From here, give the new signature group a name, and choose the signatures that you wish to define.
* Tick the relevant boxes.
* Add a useful description.
* Click **OK**
The new signature is now added, and available for use in future policy creation. 

##Creating a Network
It is very likely that you will need to define multiple networks within the organisation. **The Policy >
Networks** option allows us to do this. Click **Policy > Networks**. You will be presented with the
following screen. 

FOTO GELİCEK

To add a new network, click on:
* **Insert new network**. 

FOTO GELİCEK

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

FOTO GELİCEK

##Editing the Priority & Reliability
With OSSIM, it is possible to change the priority and reliability rating of signatures detected on the
network. This is an extremely useful facility as it gives the administrator the ability to reduce the
amount of false positives, or alert you to one specific signature type you may know you are vulnerable
to.
To change the priority and reliability settings:
* Click **Policy**
* Click **Priority & Reliability**

You will see the following screen. 

FOTO GELİCEK

To edit the priority and reliability of Back Orifice, click on the **Id** field.

As can be seen from the screenshot below, Back Orifice has the highest priority for obvious reasons.
The reliability of the Back Orifice signature has been set to 3. We can change this by simply editing
the number 3, and increasing or decreasing the number. Once this is complete, click Modify. 

