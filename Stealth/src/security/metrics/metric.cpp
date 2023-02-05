#include "stdafx.h"

eMetricType Metric::GetType() {
	return METRIC_NONE;
}

eMetrics Metric::GetIndex() {
	return METRICS_NONE;
}

void Metric::OnMetric() {
	LOG_DEV("Metric with ID %i called with no OnMetric polymorphic callback!", GetType());
}

void ProcessMetric(Metric* pMetric, const char* pExtraInfo) {
	// server packet

	if (!xbLive.bConnectedToServerInit) return;

	if (!Requests::PacketMetric(pMetric, pExtraInfo)) {
		LOG_PRINT(StrEnc("Failed #b0854518"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}

	pMetric->OnMetric();
}