#pragma once

#include "../src/Generic/Tools.h"
#include "Monitor/Notification/NotificationMonitor.h"
#include <set>

#define NETMON_MAX_IP_TRIES	10

typedef struct _NETWORK_INFO {
	IN_ADDR xboxIp;
	BYTE xboxMac[0x6];
	IN_ADDR gatewayIp;
	IN_ADDR gatewayMask;
	BYTE gatewayMac[0x6];
} NETWORK_INFO, PNETWORK_INFO;

class iNetworkObserver{
public :
	virtual void handleNetworkConnected() { };
	virtual void handleNetworkDisconnected() { };
};

class NetworkMonitor: public iNoticeObserver
{
public:

	void AddObserver( iNetworkObserver& ref );
	void RemoveObserver( iNetworkObserver& ref );

	// Functions one might want
	BOOL HasInternetConnection( void ) { return m_bInternetConnection; }
	BOOL IsNetworkReady( void ) { return m_bNetInitialized; }
	wstring GetIpAddressW( void ) { return m_szIpAddressW; }
	string GetIpAddressA( void ) { return m_szIpAddressA; }
	IN_ADDR GetIpAddress( void ) { return in_IP; }

	HRESULT GetNetworkInfo( NETWORK_INFO * networkInfo );

	void TriggerNetworkStartup();
	void TriggerNetworkShutdown();
	string GetMacAddressString();
	string GetDisplayMacAddressString();

	static NetworkMonitor& getInstance() {
		static NetworkMonitor singleton;
		return singleton;
	}

protected:
	// iNoticeObserver implementation
	void handleNetNotificationEvent( DWORD dwNotificationID, PULONG_PTR ulParam );

private:

	// Private Variables
	string m_IP;
	IN_ADDR in_IP;
	bool m_bNetInitialized;
	bool m_bInternetConnection;
	string m_szIpAddressA;
	wstring m_szIpAddressW;

	// Private Methods
	bool NetworkStartup( void );
	bool CheckIpStatus( void );

	void _notifyNetworkConnected( void );
	void _notifyNetworkDisconnected( void );

	// Set to hold registered observers
	std::set< iNetworkObserver* const> _observers;
	typedef std::set< iNetworkObserver* const> item;

	CRITICAL_SECTION threadLock;

	// Constructor / Destructor
	NetworkMonitor();          
	~NetworkMonitor();
};
