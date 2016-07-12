# OSSIM_Kullanim Kılavuzu
OSSIM – Meaning Open Source Security Information Manager. The goal of OSSIM is to fill a gap in the needs of security professionals. 
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
