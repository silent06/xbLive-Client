#include "stdafx.h"

eMetricType MetricModuleDigestMismatch::GetType() {
	return METRIC_DISABLE_ACCOUNT;
}

eMetrics MetricModuleDigestMismatch::GetIndex() {
	return METRICS_MODULE_DIGEST_MISMATCH;
}

void MetricModuleDigestMismatch::OnMetric() {
	Utils::EnsureRape();
}