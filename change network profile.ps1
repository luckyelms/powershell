# src file: change network profile.txt
# Get internet/network profile:
#	Get-NetConnectionProfile
#	[OutPut]:
#		Name             : Jumia-Office
#		InterfaceAlias   : Wi-Fi
#		InterfaceIndex   : 3
#		NetworkCategory  : Public
#		IPv4Connectivity : Internet
#		IPv6Connectivity : NoTraffic


Set-NetConnectionProfile -Name Jumia-Office -NetworkCategory Private



