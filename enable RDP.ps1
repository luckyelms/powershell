# Enable remote desktop (RDP) connections for admins on Windows
# scr file: enable RDP.txt

$rdppath1 = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\"	
		$rdppath2 = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\"
		
		Set-ItemProperty -Path $rdppath1 -Name “fDenyTSConnections” -Value 0

		Set-ItemProperty -Path $rdppath2 -Name “UserAuthentication” -Value 1

		Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'