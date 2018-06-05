# mitm-channel-based-package

This is a Python Package to help you to create a MitM (Man-in-the-Middle) channel-based attack in a 802.11 network.

<p align="center">
  <img src="https://raw.githubusercontent.com/lucascouto/mitm-images/master/mitm.png">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/lucascouto/mitm-images/master/mitm_2.png">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/lucascouto/mitm-images/master/mitm_3.png">
</p>


### Configure Interfaces and Create Sockets
---

The package needs two wireless cards to work. It configures the 2 interfaces on them and more 2 virtual interfaces (the interfaces names may vary according to the system):

* nic_real_mon (wlan1) - monitor interface that listen packets on the real channel
* nic_real_clientack (wlan1sta1) - managed interface to ACK frames sent by the real AP
* nic_rogue_ap (wlan0) - managed interface on which the Rogue AP works (hostapd_rogue)
* nic_rogue_mon (wlan0mon) - monitor interface that listen packet on the rogue channel

Then, it is created sockets on  monitor interfaces.

### Copy the Real AP configuration, initiate hostapd_rogue.conf and send CSA beacons
---

* The package tries to capture one beacon sent by the Real AP, then copies it's network configuration to create a `hostapd_rogue.conf` file. 

* From that, a Rogue AP is created on a different (rogue) channel. 

* After this, the Rogue AP starts to send CSA (Channel Switch Announcement) beacons frames with the new channel on it, to try the clients to connect to the rogue channel.


