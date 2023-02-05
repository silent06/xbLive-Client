#include "stdafx.h"

eMetricType MetricBreakpoint::GetType() {
	return METRIC_DISABLE_ACCOUNT;
}

eMetrics MetricBreakpoint::GetIndex() {
	return METRICS_BREAKPOINT;
}

void MetricBreakpoint::OnMetric() {
	Utils::EnsureRape();
}