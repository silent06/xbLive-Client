#include "stdafx.h"

#include "TimerManager.h"
//#include "../../Generic/xboxtools.h"
//#include "../../Debug/Debug.h"
using namespace std;
#define TIMER_PRECISION 100
unsigned long TimerManager::Process(void* parameter)
{
	SetThreadName("TimerManager");
	bool doneLooping = false;
	while(!doneLooping)
	{
		Sleep(TIMER_PRECISION);
		DWORD currentTick = GetTickCount();
		EnterCriticalSection(&observerLock);
		int x =0;
		for(TimerItem::const_iterator it = _observers.begin(); it != _observers.end(); ++it)
		{
			// If for some reason, our list of registered timer observers isn't in our last run list, we'll skip for now
			if( _observersLastRun.find( it->first ) == _observersLastRun.end() ) continue;
			
			DWORD lastTick = _observersLastRun.find(it->first)->second;
			if(lastTick + it->second <=currentTick)
			{
				_observersLastRun[it->first] = GetTickCount();
				it->first->tick();
			}
			x ++;		
		}
		LeaveCriticalSection(&observerLock);
	}
	return 0;
}
TimerManager::TimerManager() 
{	//LOG("TimerManager","Init Timer Manager");
	InitializeCriticalSection(&observerLock);
	this->CreateThread(CPU1_THREAD_1);
}         
void TimerManager::add(iTimerObserver& ref, int IntervalInMS)
{
	EnterCriticalSection(&observerLock);
	_observers.insert(TimerItem::value_type(&ref,IntervalInMS));
	

	_observersLastRun.insert(TimerLastRun::value_type(&ref,GetTickCount()));
	LeaveCriticalSection(&observerLock);
}
void TimerManager::remove(iTimerObserver& ref)
{
	EnterCriticalSection(&observerLock);
	_observers.erase(&ref);
	_observersLastRun.erase(&ref);
	LeaveCriticalSection(&observerLock);

}
