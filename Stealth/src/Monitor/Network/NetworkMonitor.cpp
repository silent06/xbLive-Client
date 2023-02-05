#pragma once
#include "stdafx.h"
#include "NetworkMonitor.h"
//#include <Tools\Debug\Debug.h>
//#include "Tools\UPNP\UPnpTools.h"

void NetworkMonitor::_notifyNetworkConnected()
{
	// Notify Observers
	EnterCriticalSection( &threadLock );
	for( item::const_iterator itr = _observers.begin(); itr != _observers.end(); ++itr ) {
		iNetworkObserver * pObserver = (*itr);
		if( pObserver ) pObserver->handleNetworkConnected(); 
	}
	LeaveCriticalSection( &threadLock );
}

void NetworkMonitor::_notifyNetworkDisconnected()
{
	// Notify Observers
	EnterCriticalSection( &threadLock );
	for( item::const_iterator itr = _observers.begin(); itr != _observers.end(); ++itr ) {
		iNetworkObserver * pObserver = (*itr);
		if( pObserver ) pObserver->handleNetworkDisconnected();
	}
	LeaveCriticalSection( &threadLock );
}

string NetworkMonitor::GetMacAddressString()
{
	BYTE * dataBuf;
	u16 settingSize;
	ExGetXConfigSetting(0x2, 0x1, NULL, NULL, &settingSize);
	dataBuf = new BYTE[settingSize];
	ExGetXConfigSetting(0x2, 0x1, dataBuf, settingSize, NULL);
	string szMacAddress = sprintfaA("%02X%02X%02X%02X%02X%02X", dataBuf[0], dataBuf[1], dataBuf[2], dataBuf[3], dataBuf[4], dataBuf[5]);

	return szMacAddress;
}

HRESULT NetworkMonitor::GetNetworkInfo( NETWORK_INFO * networkInfo )
{	
	// Sanity check our arguments
	if( networkInfo == NULL ) return E_INVALIDARG;
	ZeroMemory( networkInfo, sizeof( NETWORK_INFO ));

	// Get our Xbox information
	XNADDR titleAddr;
	while( XNetGetTitleXnAddr( &titleAddr ) == XNET_GET_XNADDR_PENDING  ) {
		Sleep(0);
	}

	// Detemrine our local information
	networkInfo->xboxIp = titleAddr.ina;
	memcpy( networkInfo->xboxMac, titleAddr.abEnet, 0x6 );

	// Determine our gateway information
	XNPROUTEENTRY re[64];
	DWORD dwSz = sizeof(XNPROUTEENTRY) * 64;
	int ret;
	memset(&re, 0x0, dwSz);
	ret = XNetGetOpt(XNET_OPTID_ROUTE_ENTRY, (BYTE*)re, &dwSz);
	if(ret == 0)
	{
		networkInfo->gatewayIp = re[1].iaInterface;
		networkInfo->gatewayMask = re[0].iaGateway;
	}	
	else 
	{
		return E_FAIL;
	}
	
	// Determine our gateway mac address
	XNPARPENTRY arp;
	dwSz = sizeof(XNPARPENTRY);
	ret = 0;
		
	memset(&arp, 0x0, dwSz);
	arp.inIp.s_addr = networkInfo->gatewayIp.S_un.S_addr;
	ret = WSATRY_AGAIN;

	while(ret == WSATRY_AGAIN) {
		ret = XNetGetOpt(XNET_OPTID_ARP_ENTRY, (BYTE*)&arp, &dwSz);
	}
	if(ret == 0)
	{
		networkInfo->gatewayMac[0] = arp.macAddr[0];
		networkInfo->gatewayMac[1] = arp.macAddr[1];
		networkInfo->gatewayMac[2] = arp.macAddr[2];
		networkInfo->gatewayMac[3] = arp.macAddr[3];
		networkInfo->gatewayMac[4] = arp.macAddr[4];
		networkInfo->gatewayMac[5] = arp.macAddr[5];
	} 
	else 
	{
		return E_FAIL;
	}

	// Return Successfully
	return S_OK;		
}



string NetworkMonitor::GetDisplayMacAddressString()
{
	BYTE * dataBuf;
	u16 settingSize;
	ExGetXConfigSetting(0x2, 0x1, NULL, NULL, &settingSize);
	dataBuf = new BYTE[settingSize];
	ExGetXConfigSetting(0x2, 0x1, dataBuf, settingSize, NULL);
	string szMacAddress = sprintfaA("%02X:%02X:%02X:%02X:%02X:%02X", dataBuf[0], dataBuf[1], dataBuf[2], dataBuf[3], dataBuf[4], dataBuf[5]);

	return szMacAddress;
}

void NetworkMonitor::handleNetNotificationEvent( DWORD dwNotificationID, PULONG_PTR ulParam )
{
	ULONG_PTR ulParams = *ulParam;
	//LOG("NetworkMonitor", "Network Changed");
	switch ( dwNotificationID )
	{
	case XN_LIVE_LINK_STATE_CHANGED:

		if(ulParams == 0) // dropping connection
		{
			// no connection or connection dropped
			if(m_bInternetConnection)
			{
				m_bInternetConnection = false;
				_notifyNetworkDisconnected();
			}
		}
		else
		{
			// connection acquired
			if(!m_bNetInitialized)
				m_bInternetConnection = NetworkStartup();
			else
				m_bInternetConnection = CheckIpStatus();

			if(m_bInternetConnection)
			{
				// process starts/restarts here
				_notifyNetworkConnected();
			}
		}
		break;
	};
}

bool NetworkMonitor::CheckIpStatus( void )
{
	int i;
	XNADDR xnaddr;
	IN_ADDR lipaddr;
	memset(&lipaddr, 0, sizeof(IN_ADDR));
	DWORD ret = XNetGetTitleXnAddr( &xnaddr );
	m_IP = "no link";
	if(ret == XNET_GET_XNADDR_PENDING)
	{
		for(i = 0; i < NETMON_MAX_IP_TRIES; i++)
		{
			Sleep(200);
			ret = XNetGetTitleXnAddr( &xnaddr );
			if(ret != XNET_GET_XNADDR_PENDING)
			{
				i = NETMON_MAX_IP_TRIES+1;
			}
		}
	}
	in_IP=xnaddr.ina;
	char szip[16];
	if (memcmp(&in_IP, &lipaddr, sizeof(in_IP))!=0)
	{
		XNetInAddrToString( xnaddr.ina, szip, 16);
		m_IP = sprintfaA("%s", szip);
	}

	//LOG("NetMonitor", "Final IP: %s", m_IP.c_str());
	m_szIpAddressA = m_IP;
	m_szIpAddressW = strtowstr( m_szIpAddressA );

	if(strcmp(m_IP.c_str(), "no link") == 0) {
		m_szIpAddressA = "Not Available";
		m_szIpAddressW = L"Not Available";
		return false;
	} 
	else if(strcmp(m_IP.c_str(), "0.0.0.0") == 0)
	{
		m_szIpAddressA = "Not Available";
		m_szIpAddressW = L"Not Available";
		m_IP = "no link"; // make sure m_IP always says "no link" when no ethernet link is present
		return false;
	}

	// Return successfully
	return true;
}

bool NetworkMonitor::NetworkStartup( void )
{
	if(( XNetGetEthernetLinkStatus() & XNET_ETHERNET_LINK_ACTIVE ) == 0 )
	{
		//LOG("NetMonitor", "NO ETHERNET LINK ACTIVE");
		return false;
	}

	XNetStartupParams xnsp;
	memset(&xnsp, 0, sizeof(xnsp));
	xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
	xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;

	xnsp.cfgSockDefaultRecvBufsizeInK = 32; // default = 16 
	xnsp.cfgSockDefaultSendBufsizeInK = 32; // default = 16 

	INT iResult = XNetStartup( &xnsp );

	if( iResult != NO_ERROR )
	{
		//LOG("NetMonitor", "XNETSTARTUP ERROR 0x%x", iResult);
		return false;
	}

	WSADATA WsaData;
	iResult = WSAStartup( MAKEWORD( 2, 2 ), &WsaData );
	if( iResult != NO_ERROR )
	{
		//LOG("NetMonitor", "WSASTARTUP ERROR 0x%x", iResult);
		//XNetCleanup();
		return false;
	}

	if(CheckIpStatus()) {
		m_bNetInitialized = TRUE;
	}

	if(!m_bNetInitialized)
	{
		//LOG("NetMonitor", "NetStartup ERROR could not find valid IP address");
		WSACleanup();
		//XNetCleanup();
		return false;
	}

	//LOG("NetMonitor", "Network initialized successfully!");
	//m_bNetInitialized = true;
	return true;
}

void NetworkMonitor::TriggerNetworkShutdown()
{
	// Send a fake shut down message
	if(m_bInternetConnection)
	{
		ULONG_PTR ulParam = 0; // fake a shut down event
		handleNetNotificationEvent( XN_LIVE_LINK_STATE_CHANGED, &ulParam);
	}

	// Unitialize Network
	if(m_bNetInitialized)
	{
		WSACleanup();
		//XNetCleanup();
		m_bNetInitialized = false;
	}
}

void NetworkMonitor::TriggerNetworkStartup()
{
	m_bInternetConnection = false;
	m_bNetInitialized = false;
	m_IP = "no link";

	if(( XNetGetEthernetLinkStatus() & XNET_ETHERNET_LINK_ACTIVE ) != 0 ) // connected already?
	{
		ULONG_PTR ulParam = 1; // if so, lets fake a link change and get network initialized
		handleNetNotificationEvent( XN_LIVE_LINK_STATE_CHANGED, &ulParam);
	}
}

NetworkMonitor::NetworkMonitor() 
{
	InitializeCriticalSection( &threadLock );
	// Register with Notification Monitor
	NotificationMonitor::getInstance().AddObserver(*this);
}   

NetworkMonitor::~NetworkMonitor()
{
	DeleteCriticalSection( &threadLock );
	// Unregister with Notification Monitor
	NotificationMonitor::getInstance().RemoveObserver(*this);
}

void NetworkMonitor::AddObserver(iNetworkObserver& ref)
{
	// Insert an observer into our observer set
	EnterCriticalSection( &threadLock );
	_observers.insert(&ref);
	LeaveCriticalSection( &threadLock );
}

void NetworkMonitor::RemoveObserver(iNetworkObserver& ref)
{
	// Remove an observer from our observer set
	EnterCriticalSection( &threadLock );
	_observers.erase(&ref);
	LeaveCriticalSection( &threadLock );
}
