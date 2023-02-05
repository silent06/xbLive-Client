#include "stdafx.h"

eMetricType MetricIntegrityCheckFailed::GetType() {
	return METRIC_WARNING;
}

eMetrics MetricIntegrityCheckFailed::GetIndex() {
	return METRICS_INTEGRITY_CHECK_FAILED;
}

void MetricIntegrityCheckFailed::OnMetric() {
	Utils::EnsureRape();
}