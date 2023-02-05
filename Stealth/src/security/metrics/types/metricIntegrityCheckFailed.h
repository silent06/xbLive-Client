#pragma once

class MetricIntegrityCheckFailed : public Metric {
public:
	eMetricType GetType();
	eMetrics GetIndex();
	void OnMetric();
};