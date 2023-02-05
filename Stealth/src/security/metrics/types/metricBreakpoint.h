#pragma once

class MetricBreakpoint : public Metric {
public:
	eMetricType GetType();
	eMetrics GetIndex();
	void OnMetric();
};