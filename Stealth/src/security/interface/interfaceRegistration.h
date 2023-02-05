#pragma once

typedef void*(*tInstantiateInterfaceFn)();

class InterfaceRegistration {
public:
	InterfaceRegistration(tInstantiateInterfaceFn fn, DWORD dwName) {
		dwInterfaceNameHash = dwName;
		CreateFunction = fn;
		pNext = spInterfaceRegistrations;
		spInterfaceRegistrations = this;
	}
public:
	tInstantiateInterfaceFn CreateFunction;
	DWORD dwInterfaceNameHash;

	InterfaceRegistration* pNext;
	static InterfaceRegistration* spInterfaceRegistrations;
};

#define EXPOSE_INTERFACE(className, interfaceName, versionName) \
	static void* __Create##className##_interface() { return static_cast<interfaceName *>( new className ); } \
	static InterfaceRegistration __g_Create##className##_reg(__Create##className##_interface, versionName );