NMU-CS442-PCAP
==============
<b>Northern Michigan University <br />
Advanced Network Programming<br />
Author:</b> Robert Fugate<br />
<b>Purpose:</b> Breakdown a packet into its specific parts

Items Decoded:
<ol>
<li>Ethernet source MAC address</li>
<li>Ethernet destination MAC address</li>
<li>Ethernet type</li>
<li>Ethernet length</li>
<li>Data</li>
<li>If it's an IP Packet</li>
	<ol>
	<li>Sender</li>
	<li>Receiver</li>
	<li>Version</li>
	<li>Internet Header Length</li>
	<li>Total Length</li>
	<li>Time to Live</li>
	<li>Protocol</li>
	<li>Padded</li>
	</ol>
<li>If it's a TCP Packet</li>
	<ol>
	<li>Source Port</li>
	<li>Destination Port</li>
	<li>Sequence Number</li>
	<li>Acknowledgement</li>
	<li>FIN bit</li>
	<li>SYN bit</li>
	<li>ACK bit</li>
	</ol>
<li>If it's a UDP packet</li>
	<ol>
	<li>Source Port</li>
	<li>Destination Port</li>
	<li>Length</li>
	<li>Checksum</li>
	</ol>
</ol>
