#include "stdafx.h"
#include "NotificationMonitor.h"

//#include "../../Generic/xboxtools.h"
#include "Managers/Timers/TimerManager.h"
//#include "../../Debug/Debug.h"

using namespace std;

void NotificationMonitor::_NotifyDVDEvent(DWORD dwNotificationID, PULONG_PTR ulParam)
{
	//LOG("NotificationMonitor", "DVD Event has been triggered.");
	for(item::const_iterator it = _observers.begin(); it != _observers.end(); ++it) {
		it->first->handleDVDNotificationEvent( dwNotificationID, ulParam );
	}
}

void NotificationMonitor::_NotifySignInEvent(DWORD dwNotificationID, PULONG_PTR ulParam)
{
	//LOG("NotificationMonitor", "Sign In Event has been triggered.");
	for(item::const_iterator it = _observers.begin(); it != _observers.end(); ++it) {
		it->first->handleSignInNotificationEvent( dwNotificationID, ulParam );
	}
}

void NotificationMonitor::_NotifyAvatarChangedEvent( DWORD dwNotificationID, PULONG_PTR ulParam )
{
	//LOG("NotificationMonitor", "Avatar Changed Event has been triggered.");
	for(item::const_iterator it = _observers.begin(); it != _observers.end(); ++it) {
		it->first->handleAvatarChangedNotificationEvent( dwNotificationID, ulParam );
	}
}

void NotificationMonitor::_NotifyStorageDevicesChangedEvent( DWORD dwNotificationID, PULONG_PTR ulParam )
{
	//LOG("NotificationMonitor", "Devices Changed Event has been triggered.");
	for(item::const_iterator it = _observers.begin(); it != _observers.end(); ++it) {
		it->first->handleDevicesChangedNotificationEvent( dwNotificationID, ulParam );
	}
}

void NotificationMonitor::_NotifyProfileSettingsChangedEvent( DWORD dwNotificationID, PULONG_PTR ulParam )
{
	//LOG("NotificationMonitor", "Profile Settings Changed Event has been triggered.");
	for(item::const_iterator it = _observers.begin(); it != _observers.end(); ++it) {
		it->first->handleProfileSettingsChangedNotificationEvent( dwNotificationID, ulParam );
	}
}

void NotificationMonitor::_NotifyNetworkStateEvent( DWORD dwNotificationID, PULONG_PTR ulParam )
{
	//LOG("NotificationMonitor", "Network State Event has been triggered.");
	for(item::const_iterator it = _observers.begin(); it != _observers.end(); ++it) {
		it->first->handleNetNotificationEvent( dwNotificationID, ulParam );
	}
}

void NotificationMonitor::_NotifyKinectStateEvent( DWORD dwNotificationID, PULONG_PTR ulParam )
{
	//LOG("NotificationMonitor", "Kinect State Event has been triggered.");
	for(item::const_iterator it = _observers.begin(); it != _observers.end(); ++it) {
		it->first->handleKinectNotificationEvent( dwNotificationID, ulParam );
	}
}


void NotificationMonitor::tick() {
	CheckForNotifications();
}

NotificationMonitor::NotificationMonitor() {
	// Constructor
	TimerManager::getInstance().add(*this, 250);
	
	m_hNotification = XamNotifyCreateListenerInternal( (XNOTIFY_SYSTEM|XNOTIFY_LIVE), 1, 8 );
	if( m_hNotification == NULL || m_hNotification == INVALID_HANDLE_VALUE) {
		//LOG("NotificationMonitor", "Failed to Create Listener");
		return;
	}
}

NotificationMonitor::~NotificationMonitor() {
	TimerManager::getInstance().remove(*this);
}
void NotificationMonitor::AddObserver(iNoticeObserver& ref)
{
	_observers.insert(item::value_type(&ref,&ref));
}

void NotificationMonitor::RemoveObserver(iNoticeObserver& ref)
{
	_observers.erase(&ref);
}

void NotificationMonitor::CheckForNotifications( void )
{
	DWORD dwNotificationID;
	ULONG_PTR ulParam;

	if( XNotifyGetNext( m_hNotification, 0, &dwNotificationID, &ulParam ) )
	{
		switch ( dwNotificationID )
		{
		case XN_SYS_DVDSTATECHANGED:	// Send to DVD Notice Observer
			_NotifyDVDEvent( dwNotificationID, &ulParam );
			break;
		case XN_SYS_PROFILESETTINGCHANGED:
			_NotifyProfileSettingsChangedEvent( dwNotificationID, &ulParam );
			break;
		case XN_SYS_SIGNINCHANGED:		// Send to Sign In Notice Observer
			_NotifySignInEvent( dwNotificationID, &ulParam );
			break;
		case XN_SYS_AVATARCHANGED:		// Sent to AvatarChange Notice Observer
			_NotifyAvatarChangedEvent( dwNotificationID, &ulParam );
		case XN_SYS_STORAGEDEVICESCHANGED:		// Sent to DevicesChanged Notice Observer
			_NotifyStorageDevicesChangedEvent( dwNotificationID, &ulParam );
			break;
		case XN_SYS_NUIHARDWARESTATUSCHANGED:	// Sent to Kinect Notice Observer
			_NotifyKinectStateEvent( dwNotificationID, &ulParam );
			break;
		case XN_LIVE_LINK_STATE_CHANGED: // network connection was attained or dropped
			_NotifyNetworkStateEvent( dwNotificationID, &ulParam );
			break;
		default:
			break;
		};
	}
}